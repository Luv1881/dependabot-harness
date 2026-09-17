"""npm/TS adapter. `@npmcli/arborist` for the true tree, then a TS call graph (M10+).

Dynamic import, monkey-patching, and bundling make this ecosystem unreliable — hence the
0.55 ceiling. It must never produce a high-confidence `not_affected` verdict; the
central clamp in :meth:`EcosystemAdapter.clamp` enforces that.
"""

from __future__ import annotations

import json
from typing import Any

from .base import Dependency, EcosystemAdapter, Scope, ScopeResult, UnparsableManifest

_RUNTIME_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")
_DEV_FIELDS = ("devDependencies",)

_MAX_NESTING = 200
"""npm v1 lockfiles nest a package's own dependencies arbitrarily deep. Bounded so a
hostile file reports as unparsable rather than exhausting the interpreter stack."""


class NpmAdapter(EcosystemAdapter):
    ecosystem = "npm"
    manifests = ("package.json",)

    def confidence_ceiling(self) -> float:
        return 0.55

    def parse_dependencies(self, manifest_text: str) -> list[Dependency]:
        """Resolved dependencies from a lockfile.

        Two on-disk shapes are in the wild and both matter. ``lockfileVersion`` 2 and 3
        carry a flat ``packages`` map; version 1 — npm 6 and earlier, which is still
        plenty of repositories — carries a ``dependencies`` tree nested by install path,
        in which the same package legitimately appears more than once at different
        versions. Reading only the modern shape finds nothing at all in the older one,
        and finds it silently: zero dependencies, complete coverage, a clean report over
        a lockfile full of vulnerable packages.

        A file that parses as JSON but matches neither shape is refused rather than
        reported as empty, for the same reason.
        """
        try:
            data = json.loads(manifest_text)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict):
            return []

        if isinstance(data.get("packages"), dict):
            return _from_flat_packages(data["packages"])
        if isinstance(data.get("dependencies"), dict):
            return _from_v1_tree(data["dependencies"])
        if not data:
            return []
        raise UnparsableManifest(
            "lockfile has neither a 'packages' map nor a 'dependencies' tree"
        )

    def resolve_scope(self, manifest_text: str, package: str) -> ScopeResult:
        try:
            data = json.loads(manifest_text)
        except json.JSONDecodeError:
            return ScopeResult(Scope.UNKNOWN, None, "package.json:unparsable")
        if not isinstance(data, dict):
            return ScopeResult(Scope.UNKNOWN, None, "package.json:unparsable")

        for field in _RUNTIME_FIELDS:
            if package in (data.get(field) or {}):
                return ScopeResult(Scope.RUNTIME, True, f"package.json:{field}")
        for field in _DEV_FIELDS:
            if package in (data.get(field) or {}):
                return ScopeResult(Scope.DEVELOPMENT, True, f"package.json:{field}")
        return ScopeResult(Scope.UNKNOWN, False, "package.json:transitive")


def _from_flat_packages(packages: dict[str, Any]) -> list[Dependency]:
    """lockfileVersion 2/3: a flat map keyed by install path."""
    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for path, entry in packages.items():
        if not path or not isinstance(entry, dict) or not entry.get("version"):
            continue
        name = path.split("node_modules/")[-1]
        key = (name, str(entry["version"]))
        if not name or key in seen:
            continue
        seen.add(key)
        out.append(
            Dependency(
                name=name,
                version=str(entry["version"]),
                scope=Scope.DEVELOPMENT if entry.get("dev") else Scope.RUNTIME,
            )
        )
    return out


def _from_v1_tree(
    tree: dict[str, Any], *, depth: int = 0, dev: bool = False
) -> list[Dependency]:
    """lockfileVersion 1: nested by install path, so a package may repeat.

    Depth is bounded, and a file deeper than the bound is refused rather than truncated.
    Truncating would silently drop exactly the transitive dependencies most likely to be
    vulnerable, while leaving the scan reporting complete coverage.
    """
    if depth > _MAX_NESTING:
        raise UnparsableManifest(f"dependency tree nested deeper than {_MAX_NESTING} levels")

    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for name, entry in tree.items():
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        is_dev = dev or bool(entry.get("dev"))
        if version and (name, str(version)) not in seen:
            seen.add((name, str(version)))
            out.append(
                Dependency(
                    name=name,
                    version=str(version),
                    scope=Scope.DEVELOPMENT if is_dev else Scope.RUNTIME,
                )
            )
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            for dependency in _from_v1_tree(nested, depth=depth + 1, dev=is_dev):
                key = (dependency.name, dependency.version)
                if key not in seen:
                    seen.add(key)
                    out.append(dependency)
    return out
