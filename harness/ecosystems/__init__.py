"""Ecosystem adapter registry."""

from __future__ import annotations

from .base import (
    GITHUB_ECOSYSTEM_ALIASES,
    CallSite,
    DependencyTree,
    EcosystemAdapter,
    ReachabilityLevel,
    ReachabilityResult,
    Scope,
    ScopeResult,
)
from .golang import GoAdapter
from .java import JavaAdapter
from .npm import NpmAdapter
from .python import PythonAdapter
from .rust import RustAdapter

_ADAPTERS: dict[str, EcosystemAdapter] = {
    a.ecosystem: a
    for a in (GoAdapter(), PythonAdapter(), NpmAdapter(), JavaAdapter(), RustAdapter())
}


def get_adapter(github_ecosystem: str) -> EcosystemAdapter | None:
    """Resolve a GitHub ecosystem string to an adapter, or None if unsupported.

    None is a real answer: an unsupported ecosystem must be reported as
    `could_not_determine`, never silently treated as safe.
    """
    key = GITHUB_ECOSYSTEM_ALIASES.get(github_ecosystem.lower(), github_ecosystem.lower())
    return _ADAPTERS.get(key)


def supported_ecosystems() -> tuple[str, ...]:
    return tuple(sorted(_ADAPTERS))


__all__ = [
    "CallSite",
    "DependencyTree",
    "EcosystemAdapter",
    "GoAdapter",
    "JavaAdapter",
    "NpmAdapter",
    "PythonAdapter",
    "ReachabilityLevel",
    "ReachabilityResult",
    "RustAdapter",
    "Scope",
    "ScopeResult",
    "get_adapter",
    "supported_ecosystems",
]
