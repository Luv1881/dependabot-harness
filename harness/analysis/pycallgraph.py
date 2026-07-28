"""AST-based import and call analysis for Python.

Python resolves names at runtime, so this can prove a symbol *is* referenced but never
that it is not. Callers treat a negative as weak evidence, which is why the Python
adapter's confidence ceiling sits at 0.75 rather than Go's 0.95.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

_SKIP_DIRS = frozenset(
    {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist", ".tox"}
)
_DYNAMIC_CALLS = frozenset({"__import__", "importlib"})


@dataclass
class SymbolReference:
    file: str
    line: int
    symbol: str
    kind: str = "call"


@dataclass
class PythonAnalysis:
    parsed_files: int = 0
    unparsable_files: list[str] = field(default_factory=list)
    imports: dict[str, list[SymbolReference]] = field(default_factory=dict)
    references: list[SymbolReference] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    """Local name -> the imported name it refers to, for `import X as Y` forms."""
    uses_dynamic_import: bool = False

    @property
    def scanned(self) -> bool:
        return self.parsed_files > 0

    def imports_module(self, module: str) -> bool:
        root = module.split(".")[0].lower()
        return any(key.split(".")[0].lower() == root for key in self.imports)

    def references_symbol(self, symbol: str) -> list[SymbolReference]:
        """References to a dotted symbol, matched on its final component and its parent.

        `urllib3.util.retry.Retry` is matched by a call to `Retry(...)` or to
        `retry.Retry(...)`, because an AST cannot resolve the full path to the import it
        came from without a type checker.
        """
        parts = symbol.split(".")
        leaf = parts[-1]
        parent = parts[-2] if len(parts) > 1 else None
        out: list[SymbolReference] = []
        for reference in self.references:
            resolved = self._resolve(reference.symbol)
            tail = resolved.split(".")
            if tail[-1] != leaf:
                continue
            if parent and len(tail) > 1 and tail[-2] != parent:
                continue
            out.append(reference)
        return out

    def _resolve(self, name: str) -> str:
        """Expand a local alias back to the name it was imported under.

        Without this, `from urllib3.util.retry import Retry as R` followed by `R(3)`
        reads as a call to something unrelated, and a genuinely reachable symbol is
        reported as unreferenced.
        """
        head, _, rest = name.partition(".")
        target = self.aliases.get(head)
        if target is None:
            return name
        return f"{target}.{rest}" if rest else target


def analyze(root: Path) -> PythonAnalysis:
    analysis = PythonAnalysis()
    if not root.is_dir():
        return analysis

    for path in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, ValueError):
            analysis.unparsable_files.append(str(path.relative_to(root)))
            continue

        analysis.parsed_files += 1
        relative = str(path.relative_to(root))
        _walk(tree, relative, analysis)

    return analysis


def _walk(tree: ast.AST, relative: str, analysis: PythonAnalysis) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                analysis.imports.setdefault(alias.name, []).append(
                    SymbolReference(relative, node.lineno, alias.name, kind="import")
                )
                if alias.asname:
                    analysis.aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                full = f"{module}.{alias.name}" if module else alias.name
                analysis.imports.setdefault(module or alias.name, []).append(
                    SymbolReference(relative, node.lineno, full, kind="import")
                )
                analysis.aliases[alias.asname or alias.name] = full
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name:
                analysis.references.append(SymbolReference(relative, node.lineno, name))
                if name.split(".")[0] in _DYNAMIC_CALLS:
                    analysis.uses_dynamic_import = True
        elif isinstance(node, ast.Attribute):
            name = _call_name(node)
            if name:
                analysis.references.append(
                    SymbolReference(relative, node.lineno, name, kind="attribute")
                )


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None
