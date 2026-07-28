"""npm/TS adapter. `@npmcli/arborist` for the true tree, then a TS call graph (M10+).

Dynamic import, monkey-patching, and bundling make this ecosystem unreliable — hence the
0.55 ceiling. It must never produce a high-confidence `not_affected` verdict; the
central clamp in :meth:`EcosystemAdapter.clamp` enforces that.
"""

from __future__ import annotations

import json

from .base import Dependency, EcosystemAdapter, Scope, ScopeResult

_RUNTIME_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")
_DEV_FIELDS = ("devDependencies",)


class NpmAdapter(EcosystemAdapter):
    ecosystem = "npm"
    manifests = ("package.json",)

    def confidence_ceiling(self) -> float:
        return 0.55

    def parse_dependencies(self, manifest_text: str) -> list[Dependency]:
        """Reads package-lock.json; package.json carries ranges, not resolved versions."""
        try:
            data = json.loads(manifest_text)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict):
            return []

        out: list[Dependency] = []
        for path, entry in (data.get("packages") or {}).items():
            if not path or not isinstance(entry, dict) or not entry.get("version"):
                continue
            name = path.split("node_modules/")[-1]
            out.append(
                Dependency(
                    name=name,
                    version=str(entry["version"]),
                    scope=Scope.DEVELOPMENT if entry.get("dev") else Scope.RUNTIME,
                )
            )
        return out

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
