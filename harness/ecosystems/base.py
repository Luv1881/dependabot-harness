"""EcosystemAdapter ABC and shared value types (§9).

M1 implements only :meth:`EcosystemAdapter.resolve_scope` and
:meth:`confidence_ceiling` — the deterministic manifest facts ingest needs. Reachability
lands in M3 (Go first) and stays ``NotImplementedError`` until then, so a missing
implementation fails loudly rather than silently returning "not reachable".
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

GITHUB_ECOSYSTEM_ALIASES = {
    "go": "go",
    "gomod": "go",
    "pip": "pip",
    "pypi": "pip",
    "npm": "npm",
    "maven": "maven",
    "rust": "cargo",
    "cargo": "cargo",
    "nuget": "nuget",
    "composer": "composer",
    "rubygems": "rubygems",
    "actions": "actions",
    "pub": "pub",
    "swift": "swift",
}


class Scope(str):
    """Dependency scope. `unknown` is distinct from `runtime` and must stay so."""

    RUNTIME = "runtime"
    DEVELOPMENT = "development"
    UNKNOWN = "unknown"


class ReachabilityLevel(IntEnum):
    """The §9 scale. Ordering is meaningful; do not renumber."""

    ABSENT = 0
    PRESENT = 1
    IMPORTED = 2
    SYMBOL_REFERENCED = 3
    PATH_FROM_ENTRY = 4
    ATTACKER_CONTROLLED = 5


REACHABILITY_SCALE: dict[str, str] = {
    "0": "package absent from resolved tree",
    "1": "package present, never imported",
    "2": "imported, vulnerable symbol not referenced",
    "3": "vulnerable symbol referenced, path from entry point unproven",
    "4": "call path from an entry point to vulnerable symbol exists",
    "5": "call path exists and carries attacker-controlled input",
}


@dataclass(frozen=True)
class Dependency:
    """One resolved dependency read out of a manifest or lockfile."""

    name: str
    version: str
    scope: str = Scope.UNKNOWN
    is_direct: bool | None = None

    @property
    def is_pinned(self) -> bool:
        """Whether the version is exact enough to query an advisory database with."""
        return bool(self.version) and not any(c in self.version for c in "^~><*=| ")


@dataclass(frozen=True)
class ScopeResult:
    """What the manifest/lockfile actually says, not what Dependabot guessed.

    Dependabot's own ``dependencyScope`` is unreliable for transitive dependencies, which
    is why §5.4 requires resolving this from the manifest.
    """

    scope: str = Scope.UNKNOWN
    is_direct: bool | None = None
    source: str = "unresolved"


@dataclass
class DependencyTree:
    root: str
    edges: dict[str, list[str]] = field(default_factory=dict)
    resolved: dict[str, str] = field(default_factory=dict)

    def path_to(self, package: str) -> list[str]:
        """Shortest dependency path root → package, or [] if unreachable in the tree."""
        seen = {self.root}
        queue: list[list[str]] = [[self.root]]
        while queue:
            path = queue.pop(0)
            for child in self.edges.get(path[-1], []):
                if child == package:
                    return [*path, child]
                if child not in seen:
                    seen.add(child)
                    queue.append([*path, child])
        return []


@dataclass
class CallSite:
    file: str
    line: int
    symbol: str
    snippet: str = ""
    nearest_entry_point: str | None = None
    behind_auth: bool | None = None


@dataclass
class ReachabilityResult:
    """Toolchain output. ``method='failed'`` with ``confidence=0.0`` is the *only*
    correct representation of a toolchain failure — never ``level=0`` (§14.3)."""

    level: ReachabilityLevel
    confidence: float
    method: str
    tool_version: str = ""
    call_sites: list[CallSite] = field(default_factory=list)
    dependency_path: list[str] = field(default_factory=list)
    truncated: bool = False
    error: str | None = None

    @classmethod
    def failed(cls, method: str, error: str) -> ReachabilityResult:
        return cls(
            level=ReachabilityLevel.ABSENT,
            confidence=0.0,
            method="failed",
            call_sites=[],
            error=f"{method}: {error}",
        )

    @property
    def is_failure(self) -> bool:
        return self.method == "failed"


class EcosystemAdapter(ABC):
    """One per package ecosystem. Runs the real SCA tooling; the agent never does."""

    ecosystem: str
    manifests: tuple[str, ...] = ()

    def dev_scope_is_conclusive(self) -> bool:
        """Whether development scope alone proves the package is absent from production.

        True only where the build system structurally excludes the scope from the
        shipped artifact. Where a bundler or packaging step can still pull a dev-scoped
        dependency into production, this is False and the claim needs build targets.
        """
        return False

    @abstractmethod
    def confidence_ceiling(self) -> float:
        """Hard cap on ``reachability.confidence`` for this ecosystem (§9)."""

    @abstractmethod
    def resolve_scope(self, manifest_text: str, package: str) -> ScopeResult:
        """Resolve runtime/dev scope and directness from manifest text (§5.4)."""

    def parse_dependencies(self, manifest_text: str) -> list[Dependency]:
        """Resolved dependencies from one manifest.

        Used to query an advisory database directly when Dependabot's own alerts are not
        reachable. An adapter that cannot resolve versions returns nothing rather than
        guessing: an unpinned dependency cannot be matched against an advisory range.
        """
        return []

    def resolve_tree(self, repo_path: Path) -> DependencyTree:
        raise NotImplementedError(f"{self.ecosystem}: resolve_tree lands in M3+")

    def reachability(self, repo_path: Path, alert: Any) -> ReachabilityResult:
        raise NotImplementedError(f"{self.ecosystem}: reachability lands in M3+")

    def call_sites(self, repo_path: Path, symbols: list[str]) -> list[CallSite]:
        raise NotImplementedError(f"{self.ecosystem}: call_sites lands in M3+")

    def clamp(self, result: ReachabilityResult, *, symbols_known: bool) -> ReachabilityResult:
        """Enforce the ceiling (§9) and the unknown-symbols cap (§14.5).

        Applied centrally so no adapter can accidentally exceed its own ceiling.
        """
        ceiling = self.confidence_ceiling()
        level = result.level
        confidence = min(result.confidence, ceiling)
        if not symbols_known and not result.is_failure:
            level = min(level, ReachabilityLevel.IMPORTED)
            confidence = min(confidence, 0.5)
        if result.is_failure:
            confidence = 0.0
        return ReachabilityResult(
            level=level,
            confidence=confidence,
            method=result.method,
            tool_version=result.tool_version,
            call_sites=result.call_sites,
            dependency_path=result.dependency_path,
            truncated=result.truncated,
            error=result.error,
        )
