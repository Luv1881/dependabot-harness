"""Evidence bundle construction.

The agent never runs the SCA tools; it receives their output through this bundle. The
builder owns three invariants the rest of the system depends on:

- confidence never exceeds the ecosystem adapter's ceiling
- an advisory with no symbol data caps level at 2 and confidence at 0.5
- a toolchain failure is ``confidence 0.0`` and ``method "failed"``, never ``not reachable``
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..analysis import snippets
from ..db import AlertRecord
from ..ecosystems.base import (
    REACHABILITY_SCALE,
    CallSite,
    EcosystemAdapter,
    ReachabilityLevel,
    ReachabilityResult,
)

MAX_CALL_SITES = 15


@dataclass
class EvidenceBundle:
    alert_key: str
    reachability: dict[str, Any]
    advisory: dict[str, Any]
    exploitability: dict[str, Any]
    package: dict[str, Any]
    call_sites: list[dict[str, Any]] = field(default_factory=list)
    dependency_path: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def level(self) -> int:
        return int(self.reachability["level"])

    @property
    def confidence(self) -> float:
        return float(self.reachability["confidence"])

    @property
    def toolchain_failed(self) -> bool:
        return bool(self.reachability["method"] == "failed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_key": self.alert_key,
            "reachability": self.reachability,
            "dependency_path": self.dependency_path,
            "call_sites": self.call_sites,
            "advisory": self.advisory,
            "exploitability": self.exploitability,
            "package": self.package,
            "truncated": self.truncated,
        }


class EvidenceBuilder:
    def __init__(self, adapter: EcosystemAdapter, *, max_call_sites: int = MAX_CALL_SITES) -> None:
        self.adapter = adapter
        self.max_call_sites = max_call_sites

    def build(
        self,
        alert: AlertRecord,
        result: ReachabilityResult,
        *,
        repo_root: Path | None = None,
        advisory_summary: str = "",
    ) -> EvidenceBundle:
        clamped = self.adapter.clamp(result, symbols_known=alert.symbols_known)
        sites, truncated = self._call_sites(clamped.call_sites, repo_root)

        return EvidenceBundle(
            alert_key=alert.alert_key,
            reachability={
                "level": int(clamped.level),
                "scale": dict(REACHABILITY_SCALE),
                "confidence": round(clamped.confidence, 4),
                "method": clamped.method,
                "tool_version": clamped.tool_version,
                "error": clamped.error,
            },
            dependency_path=list(clamped.dependency_path),
            call_sites=sites,
            advisory={
                "ghsa_id": alert.ghsa_id,
                "cve_id": alert.cve_id,
                "summary": advisory_summary,
                "affected_symbols": list(alert.symbols or []),
                "symbols_known": alert.symbols_known,
            },
            exploitability={
                "cvss": alert.cvss_score,
                "epss": alert.epss_score,
                "in_kev": alert.in_kev,
                "severity": alert.severity,
            },
            package={
                "purl": alert.purl,
                "ecosystem": alert.ecosystem,
                "resolved_version": alert.resolved_ver,
                "patched_version": alert.patched_ver,
                "manifest_path": alert.manifest_path,
                "dep_scope": alert.dep_scope,
                "is_direct": alert.is_direct,
            },
            truncated=truncated or clamped.truncated,
        )

    def _call_sites(
        self, sites: list[CallSite], repo_root: Path | None
    ) -> tuple[list[dict[str, Any]], bool]:
        truncated = len(sites) > self.max_call_sites
        selected = sites[: self.max_call_sites]
        out: list[dict[str, Any]] = []
        for site in selected:
            relative = snippets.to_relative(repo_root, site.file) if repo_root else site.file
            snippet = snippets.extract(repo_root, relative, site.line).text if repo_root else ""
            out.append(
                {
                    "file": relative,
                    "line": site.line,
                    "symbol": site.symbol,
                    "snippet": snippet,
                    "nearest_entry_point": site.nearest_entry_point,
                    "behind_auth": site.behind_auth,
                }
            )
        return out, truncated


def is_shallow(bundles: list[EvidenceBundle]) -> bool:
    """A repo whose evidence produced zero call sites across every alert.

    That is a broken toolchain, not a secure repo, so the caller requeues rather than
    trusting the emptiness.
    """
    if not bundles:
        return False
    if all(b.toolchain_failed for b in bundles):
        return True
    reached = any(b.level >= ReachabilityLevel.SYMBOL_REFERENCED for b in bundles)
    return not reached and not any(b.call_sites for b in bundles)
