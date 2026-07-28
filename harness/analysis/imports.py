"""Whole-repo import/require scanning.

An index reports whether a package name appears in any import statement. A scan that
could not run reports :attr:`ImportIndex.scanned` as False, which callers must treat as
undecidable rather than as absence.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

_MAX_FILE_BYTES = 2_000_000
_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        "target",
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "testdata",
    }
)


@dataclass
class ImportIndex:
    scanned: bool
    modules: set[str] = field(default_factory=set)
    files_scanned: int = 0
    reason: str = ""

    def contains(self, package: str) -> bool | None:
        if not self.scanned:
            return None
        return package in self.modules

    def any_prefix(self, package: str) -> bool | None:
        if not self.scanned:
            return None
        if package in self.modules:
            return True
        prefix = f"{package}/"
        dotted = f"{package}."
        return any(m.startswith(prefix) or m.startswith(dotted) for m in self.modules)

    @classmethod
    def unavailable(cls, reason: str) -> ImportIndex:
        return cls(scanned=False, reason=reason)


class ImportScanner(ABC):
    ecosystem: str
    extensions: tuple[str, ...] = ()
    supports_package_membership: bool = True
    """Whether a package coordinate can be mapped to the identifiers this scanner emits.

    False means absence from the index proves nothing about the package, so membership
    questions must be declined rather than answered.
    """

    @abstractmethod
    def extract(self, text: str) -> set[str]:
        """Module identifiers imported by one source file."""

    def normalize_package(self, package: str) -> str:
        return package

    def scan(self, root: Path) -> ImportIndex:
        if not root.is_dir():
            return ImportIndex.unavailable(f"checkout missing: {root}")
        modules: set[str] = set()
        count = 0
        for path in self._iter_files(root):
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            modules |= self.extract(text)
            count += 1
        return ImportIndex(scanned=True, modules=modules, files_scanned=count)

    def _iter_files(self, root: Path) -> Iterator[Path]:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if self.extensions and path.suffix not in self.extensions:
                continue
            yield path


class GoImportScanner(ImportScanner):
    ecosystem = "go"
    extensions = (".go",)
    _BLOCK = re.compile(r"import\s*\((.*?)\)", re.DOTALL)
    _SINGLE = re.compile(r'^\s*import\s+(?:[\w.]+\s+)?"([^"]+)"', re.MULTILINE)
    _QUOTED = re.compile(r'"([^"]+)"')

    def extract(self, text: str) -> set[str]:
        found = set(self._SINGLE.findall(text))
        for block in self._BLOCK.findall(text):
            found |= set(self._QUOTED.findall(block))
        return found


class PythonImportScanner(ImportScanner):
    ecosystem = "pip"
    extensions = (".py",)
    _IMPORT = re.compile(r"^\s*import\s+([\w.]+)", re.MULTILINE)
    _FROM = re.compile(r"^\s*from\s+([\w.]+)\s+import", re.MULTILINE)

    def extract(self, text: str) -> set[str]:
        found = set(self._IMPORT.findall(text)) | set(self._FROM.findall(text))
        return {name.split(".")[0] for name in found} | found

    def normalize_package(self, package: str) -> str:
        return re.sub(r"[-_.]+", "_", package).lower()

    def scan(self, root: Path) -> ImportIndex:
        index = super().scan(root)
        if index.scanned:
            index.modules = {m.lower() for m in index.modules}
        return index


class NpmImportScanner(ImportScanner):
    ecosystem = "npm"
    extensions = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
    _FROM = re.compile(r"""from\s+['"]([^'"]+)['"]""")
    _REQUIRE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
    _BARE_IMPORT = re.compile(r"""import\s+['"]([^'"]+)['"]""")
    _DYNAMIC = re.compile(r"""import\(\s*['"]([^'"]+)['"]\s*\)""")

    def extract(self, text: str) -> set[str]:
        found: set[str] = set()
        for pattern in (self._FROM, self._REQUIRE, self._BARE_IMPORT, self._DYNAMIC):
            found |= set(pattern.findall(text))
        return {m for m in found if not m.startswith((".", "/"))}


class JavaImportScanner(ImportScanner):
    """Java imports are Java packages; Maven coordinates are groupId:artifactId.

    The two are not derivable from each other - jackson-databind ships classes under
    com.fasterxml.jackson.databind while its groupId is com.fasterxml.jackson.core - so
    absence from this index says nothing about the coordinate.
    """

    ecosystem = "maven"
    extensions = (".java", ".kt", ".scala")
    supports_package_membership = False
    _IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.MULTILINE)

    def extract(self, text: str) -> set[str]:
        return set(self._IMPORT.findall(text))


class RustImportScanner(ImportScanner):
    ecosystem = "cargo"
    extensions = (".rs",)
    _USE = re.compile(r"^\s*(?:pub\s+)?use\s+([\w:]+)", re.MULTILINE)
    _EXTERN = re.compile(r"^\s*extern\s+crate\s+(\w+)", re.MULTILINE)
    _INTERNAL = frozenset({"crate", "self", "super"})

    def extract(self, text: str) -> set[str]:
        roots = {u.split("::")[0] for u in self._USE.findall(text)}
        found = roots - self._INTERNAL
        return found | set(self._EXTERN.findall(text))

    def normalize_package(self, package: str) -> str:
        return package.replace("-", "_")


_SCANNERS: dict[str, ImportScanner] = {
    scanner.ecosystem: scanner
    for scanner in (
        GoImportScanner(),
        PythonImportScanner(),
        NpmImportScanner(),
        JavaImportScanner(),
        RustImportScanner(),
    )
}


def build_scanner(ecosystem: str) -> ImportScanner | None:
    from ..ecosystems.base import GITHUB_ECOSYSTEM_ALIASES

    key = GITHUB_ECOSYSTEM_ALIASES.get(ecosystem.lower(), ecosystem.lower())
    return _SCANNERS.get(key)
