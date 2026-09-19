"""Independent reachability evidence, for labelling an eval case.

This exists so a golden label can be assigned from evidence the pipeline never produced.
It is a *separate* implementation of the import search, deliberately broader in what it
looks at: the pipeline's scanners read one file extension per ecosystem, while a package
can also be pulled in by a stylesheet, a script tag, a bundler alias or a build script.

Two questions it answers, and they are not the same question:

* **Is anything importing this package?** A direct-import search, scoped to the subtree
  the manifest belongs to. Scoping matters: a monorepo's ``go-sdk/go.mod`` must not be
  judged by Python files elsewhere in the same tree.
* **Is the package's code *reachable*?** For a lockfile ecosystem, a package nothing
  imports can still be shipped, because the packages that do import it depend on it. Its
  code is in the bundle and its vulnerable function can be called through its dependents.
  Answering that needs the dependency graph, not the import index.
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..fsutil import iter_repo_files

MAX_FILE_BYTES = 2_000_000
MAX_HITS = 40

_GO_SUFFIXES = (".go",)
_PY_SUFFIXES = (".py", ".pyi")
_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")
_RS_SUFFIXES = (".rs",)
_WEB_SUFFIXES = (".css", ".scss", ".sass", ".less", ".html", ".htm", ".vue")

_SKIP_NAME_HINTS = ("docs/", "doc/", "documentation/", "examples/", "testdata/")


@dataclass(frozen=True)
class Hit:
    file: str
    line: int
    text: str

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "text": self.text[:160]}


@dataclass
class Evidence:
    """What an independent search found for one package."""

    import_hits: list[Hit] = field(default_factory=list)
    web_hits: list[Hit] = field(default_factory=list)
    symbol_hits: list[Hit] = field(default_factory=list)
    scanned_files: int = 0
    scope: str = ""
    scope_was_narrowed: bool = False
    transitive_dependents: list[str] = field(default_factory=list)
    """Imported packages that depend on this one, directly or transitively. Non-empty means
    the package's code ships inside something the application does load, so 'nothing
    imports it' is not a statement about reachability."""
    graph_available: bool = False

    @property
    def directly_imported(self) -> bool:
        return bool(self.import_hits)

    @property
    def shipped_through_a_dependent(self) -> bool:
        return bool(self.transitive_dependents)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "scope_was_narrowed": self.scope_was_narrowed,
            "scanned_files": self.scanned_files,
            "directly_imported": self.directly_imported,
            "shipped_through_a_dependent": self.shipped_through_a_dependent,
            "transitive_dependents": self.transitive_dependents[:8],
            "graph_available": self.graph_available,
            "counts": {
                "imports": len(self.import_hits),
                "web": len(self.web_hits),
                "symbols": len(self.symbol_hits),
            },
            "import_examples": [h.to_dict() for h in self.import_hits[:4]],
            "web_examples": [h.to_dict() for h in self.web_hits[:4]],
            "symbol_examples": [h.to_dict() for h in self.symbol_hits[:4]],
        }


def _python_modules(package: str) -> list[str]:
    """A distribution name mapped to the import identifiers it can install.

    The mapping is not derivable in general — `pyyaml` installs `yaml`, `python-dateutil`
    installs `dateutil` — so the rule is to search for the normalised forms *and* the bare
    basename with separators removed, and to accept a hit on any of them.
    """
    normalised = re.sub(r"[-_.]+", "_", package).lower()
    candidates = {normalised, normalised.replace("_", ""), normalised.replace("_", "-")}
    return sorted(c for c in candidates if len(c) >= 3)


def _patterns(ecosystem: str, package: str) -> tuple[tuple[str, ...], list[re.Pattern[str]]]:
    """Suffixes worth reading, and the import forms to look for within them."""
    eco = {"gomod": "go", "pypi": "pip", "crates.io": "cargo"}.get(ecosystem, ecosystem)
    if eco == "go":
        # A Go import names the module path in a quoted string. Matching the bare basename
        # would light up on `host="grpc://"`, which is a URL scheme, not an import.
        escaped = re.escape(package)
        return _GO_SUFFIXES, [re.compile(rf'"{escaped}(/[^"]*)?"')]
    if eco == "pip":
        alternatives = "|".join(re.escape(m) for m in _python_modules(package))
        return _PY_SUFFIXES, [
            re.compile(rf"^\s*import\s+({alternatives})\b", re.MULTILINE),
            re.compile(rf"^\s*from\s+({alternatives})[\s.]"),
            re.compile(rf"import_module\(\s*['\"]({alternatives})['\"]"),
        ]
    if eco == "npm":
        escaped = re.escape(package)
        return _JS_SUFFIXES, [
            re.compile(rf"""require\(\s*['"]{escaped}(/[^'"]*)?['"]"""),
            re.compile(rf"""from\s+['"]{escaped}(/[^'"]*)?['"]"""),
            re.compile(rf"""import\(\s*['"]{escaped}(/[^'"]*)?['"]"""),
            re.compile(rf"""import\s+['"]{escaped}(/[^'"]*)?['"]"""),
        ]
    if eco == "cargo":
        crate = re.escape(package.replace("-", "_"))
        return _RS_SUFFIXES, [
            re.compile(rf"^\s*use\s+{crate}\b", re.MULTILINE),
            re.compile(rf"^\s*extern\s+crate\s+{crate}\b", re.MULTILINE),
        ]
    return (), []


def _web_patterns(package: str) -> list[re.Pattern[str]]:
    """A package can be pulled in without code: a stylesheet import or a script tag."""
    basename = re.escape(package.rsplit("/", 1)[-1])
    return [
        re.compile(rf"@import\s+[^;]*{basename}"),
        re.compile(rf"url\([^)]*{basename}[^)]*\)"),
        re.compile(rf"<script[^>]+src=[^>]*{basename}"),
        re.compile(rf"<link[^>]+href=[^>]*{basename}"),
    ]


def manifest_scope(root: Path, manifest_path: str) -> tuple[Path, bool]:
    """The subtree a manifest governs, and whether that narrowed the search.

    A dependency declared by ``go-sdk/go.mod`` is a dependency of the Go module in
    ``go-sdk/``. Judging it against the whole repository finds the word in unrelated
    languages and tells you nothing.
    """
    if not manifest_path:
        return root, False
    parent = (root / manifest_path).parent
    if parent == root or not parent.is_dir():
        return root, False
    return parent, True


def gather(
    root: Path,
    *,
    ecosystem: str,
    package: str,
    manifest_path: str = "",
    symbols: list[str] | None = None,
    include_web: bool = True,
) -> Evidence:
    """Search for import forms and vulnerable-symbol references. Read-only."""
    scope, narrowed = manifest_scope(root, manifest_path)
    evidence = Evidence(scope=str(scope.relative_to(root)) or ".", scope_was_narrowed=narrowed)
    suffixes, import_patterns = _patterns(ecosystem, package)
    web_patterns = _web_patterns(package) if include_web else []
    symbol_patterns = [
        re.compile(rf"(?<![A-Za-z0-9_]){re.escape(s.rsplit('.', 1)[-1])}(?![A-Za-z0-9_])")
        for s in (symbols or [])
        if len(s.rsplit(".", 1)[-1]) >= 3
    ]

    for path in iter_repo_files(scope):
        suffix = path.suffix.lower()
        if suffix not in (*suffixes, *_WEB_SUFFIXES) and not symbol_patterns:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(root))
        evidence.scanned_files += 1
        if relative.startswith(_SKIP_NAME_HINTS):
            continue

        if suffix in suffixes:
            for number, line in enumerate(text.splitlines(), start=1):
                if any(p.search(line) for p in import_patterns):
                    if len(evidence.import_hits) < MAX_HITS:
                        evidence.import_hits.append(Hit(relative, number, line.strip()))
                    break
            for number, line in enumerate(text.splitlines(), start=1):
                if any(p.search(line) for p in symbol_patterns):
                    if len(evidence.symbol_hits) < MAX_HITS:
                        evidence.symbol_hits.append(Hit(relative, number, line.strip()))
                    break
        if include_web and suffix in _WEB_SUFFIXES:
            for number, line in enumerate(text.splitlines(), start=1):
                if any(p.search(line) for p in web_patterns):
                    if len(evidence.web_hits) < MAX_HITS:
                        evidence.web_hits.append(Hit(relative, number, line.strip()))
                    break
    return evidence


def npm_dependency_graph(lockfile: str) -> dict[str, set[str]]:
    """Package name -> the names it depends on, from either lockfile shape."""
    try:
        data = json.loads(lockfile)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}

    graph: dict[str, set[str]] = {}

    def add(name: str, entry: dict[str, Any]) -> None:
        edges = graph.setdefault(name, set())
        for key in ("dependencies", "optionalDependencies", "peerDependencies"):
            block = entry.get(key)
            if isinstance(block, dict):
                edges.update(str(k) for k in block)

    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, entry in packages.items():
            if not path or not isinstance(entry, dict):
                continue
            add(path.split("node_modules/")[-1], entry)

    def walk_v1(tree: Any) -> None:
        if not isinstance(tree, dict):
            return
        for name, entry in tree.items():
            if not isinstance(entry, dict):
                continue
            add(name, entry)
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                for child, child_entry in nested.items():
                    if isinstance(child_entry, dict):
                        graph.setdefault(name, set()).add(child)
                walk_v1(nested)

    if isinstance(data.get("dependencies"), dict):
        walk_v1(data["dependencies"])
    return graph


def transitive_dependents(
    graph: dict[str, set[str]], package: str, seeds: set[str], *, limit: int = 8
) -> list[str]:
    """Imported packages that pull ``package`` in, directly or transitively.

    Walking the edges *backwards* from the package to the application's own imports. A
    non-empty result means the package is inside something the application loads, so its
    code ships and its vulnerable function can be reached through that dependent.
    """
    if package in seeds:
        return []
    reverse: dict[str, set[str]] = {}
    for parent, children in graph.items():
        for child in children:
            reverse.setdefault(child, set()).add(parent)

    found: set[str] = set()
    queue: deque[tuple[str, int]] = deque((p, 0) for p in reverse.get(package, ()))
    seen: set[str] = {package}
    while queue and len(found) < limit:
        node, depth = queue.popleft()
        if node in seen or depth > 8:
            continue
        seen.add(node)
        if node in seeds:
            found.add(node)
            continue
        for parent in reverse.get(node, ()):
            queue.append((parent, depth + 1))
    return sorted(found)[:limit]
