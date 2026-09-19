"""Which packages' code is actually in the shipped artifact.

A lockfile or manifest says what is *declared*. It does not say what is *in the build*.
A package nothing imports can still ship, because the packages that do import it depend on
it — ``handlebars`` ships inside ``hbs``, ``qs`` inside ``body-parser``, and so on. Its
vulnerable function is then callable through that dependent.

That distinction is the difference between a justified clearance and a false one.
``not_imported`` emits the CISA code ``vulnerable_code_not_present``, which is an absolute
claim about the artifact. Answering it from an import index alone is answering a question
about what the application *names* with evidence about what the application *contains*.

Each function returns ``None`` when the question cannot be answered for that ecosystem.
``None`` means "decline", never "empty": treating an unavailable answer as "nothing ships"
is the same conflation the rest of the harness refuses to make.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from ..fsutil import iter_repo_files

_MAX_FILE_BYTES = 2_000_000

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")

_MODULE_FORMS = (
    re.compile(r"""(?:require|from|import)\s*\(?\s*['"]([^'"]+)['"]"""),
    re.compile(r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
)

_GO_TIMEOUT_SECONDS = 300


def _module_name(specifier: str) -> str | None:
    """The package a module specifier resolves to, or None for a relative/path import."""
    if not specifier or specifier.startswith((".", "/", "http:", "https:", "data:", "node:")):
        return None
    parts = specifier.split("/")
    return "/".join(parts[:2]) if specifier.startswith("@") else parts[0]


def entry_imports(root: Path, ecosystem: str) -> set[str]:
    """Packages the application's own source names, excluding vendored trees.

    This is the seed set for the traversal. Sources only: a dependency name appearing in a
    config file, a Dockerfile or a CI workflow does not put its code in the bundle.
    """
    suffixes = _JS_SUFFIXES if ecosystem == "npm" else ()
    if not suffixes:
        return set()
    found: set[str] = set()
    for path in iter_repo_files(root):
        if path.suffix.lower() not in suffixes:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in _MODULE_FORMS:
            for match in pattern.finditer(text):
                name = _module_name(match.group(1))
                if name:
                    found.add(name)
    return found


def _npm_graph(lockfile: str) -> dict[str, set[str]]:
    """Package -> the packages it depends on, from either lockfile shape."""
    try:
        data = json.loads(lockfile)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}

    graph: dict[str, set[str]] = {}

    def record(name: str, entry: dict[str, object]) -> None:
        edges = graph.setdefault(name, set())
        for field in ("dependencies", "optionalDependencies", "peerDependencies"):
            block = entry.get(field)
            if isinstance(block, dict):
                edges.update(str(k) for k in block)

    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, entry in packages.items():
            if path and isinstance(entry, dict):
                record(str(path).split("node_modules/")[-1], entry)

    def walk_v1(tree: object) -> None:
        if not isinstance(tree, dict):
            return
        for name, entry in tree.items():
            if not isinstance(entry, dict):
                continue
            record(str(name), entry)
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                for child in nested:
                    graph.setdefault(str(name), set()).add(str(child))
                walk_v1(nested)

    if isinstance(data.get("dependencies"), dict):
        walk_v1(data["dependencies"])
    return graph


def _closure(graph: dict[str, set[str]], seeds: set[str]) -> set[str]:
    seen: set[str] = set()
    stack = [s for s in seeds if s in graph]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(child for child in graph.get(node, ()) if child not in seen)
    return seen


def npm_shipped(root: Path) -> set[str] | None:
    """Names in the bundle: the closure of the application's imports over the lockfile.

    None when there is no lockfile or nothing in it is importable, because an absent graph
    is not a graph that says nothing ships.
    """
    lockfile = root / "package-lock.json"
    if not lockfile.is_file():
        return None
    try:
        graph = _npm_graph(lockfile.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    if not graph:
        return None
    seeds = entry_imports(root, "npm") & set(graph)
    closure = _closure(graph, seeds)
    return closure or None


def go_shipped(root: Path) -> set[str] | None:
    """Module paths linked into the build, via the toolchain's own dependency list.

    ``go list -deps`` answers precisely the question an import scan cannot: which modules
    the compiled program actually contains. None when the toolchain is absent or the module
    does not build, both of which mean the question is unanswered rather than answered.
    """
    if not (root / "go.mod").is_file():
        return None
    try:
        proc = subprocess.run(
            ["go", "list", "-deps", "-e", "-f", "{{with .Module}}{{.Path}}{{end}}", "./..."],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=_GO_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    modules = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    return modules or None


def shipped_packages(root: Path, ecosystem: str) -> set[str] | None:
    """Dispatch by ecosystem. None means the question is not answerable here."""
    if ecosystem == "npm":
        return npm_shipped(root)
    if ecosystem in {"go", "gomod"}:
        return go_shipped(root)
    return None
