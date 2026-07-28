"""Rust adapter. `cargo audit` + `cargo-auditable`.

Monomorphization means the compiled binary's symbol table is strong evidence, which is
why the ceiling sits at 0.9 — second only to Go.
"""

from __future__ import annotations

import tomllib
from typing import Any

from .base import Dependency, EcosystemAdapter, Scope, ScopeResult


class RustAdapter(EcosystemAdapter):
    ecosystem = "cargo"
    manifests = ("Cargo.toml",)

    def dev_scope_is_conclusive(self) -> bool:
        """Cargo `dev-dependencies` and `build-dependencies` are never linked into the
        release binary."""
        return True

    def confidence_ceiling(self) -> float:
        return 0.90

    def parse_dependencies(self, manifest_text: str) -> list[Dependency]:
        """Reads Cargo.lock, which is where exact versions live."""
        out: list[Dependency] = []
        try:
            data: dict[str, Any] = tomllib.loads(manifest_text)
        except tomllib.TOMLDecodeError:
            return out
        for package in data.get("package") or []:
            if isinstance(package, dict) and package.get("name") and package.get("version"):
                out.append(
                    Dependency(
                        name=str(package["name"]),
                        version=str(package["version"]),
                        scope=Scope.RUNTIME,
                    )
                )
        return out

    def resolve_scope(self, manifest_text: str, package: str) -> ScopeResult:
        try:
            data: dict[str, Any] = tomllib.loads(manifest_text)
        except tomllib.TOMLDecodeError:
            return ScopeResult(Scope.UNKNOWN, None, "Cargo.toml:unparsable")

        if package in (data.get("dependencies") or {}):
            return ScopeResult(Scope.RUNTIME, True, "Cargo.toml:dependencies")
        if package in (data.get("dev-dependencies") or {}):
            return ScopeResult(Scope.DEVELOPMENT, True, "Cargo.toml:dev-dependencies")
        if package in (data.get("build-dependencies") or {}):
            return ScopeResult(Scope.DEVELOPMENT, True, "Cargo.toml:build-dependencies")

        for target in (data.get("target") or {}).values():
            if package in (target.get("dependencies") or {}):
                return ScopeResult(Scope.RUNTIME, True, "Cargo.toml:target.dependencies")
            if package in (target.get("dev-dependencies") or {}):
                return ScopeResult(Scope.DEVELOPMENT, True, "Cargo.toml:target.dev-dependencies")

        return ScopeResult(Scope.UNKNOWN, False, "Cargo.toml:transitive-or-absent")
