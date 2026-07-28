"""OSV-backed alert source for repositories the harness does not administer.

Dependabot's alert API requires admin scope on the target repository, so a public project
you do not own cannot be triaged through it. This source derives the same alerts from the
manifests in a checkout and OSV's batch query endpoint, and yields the identical
:class:`RawAlert` shape so every downstream stage is unchanged.

Where Dependabot reports what GitHub thinks is installed, this reports what the committed
manifests actually pin. Unpinned dependencies are skipped rather than guessed at: a range
cannot be matched against an advisory's affected versions.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ..cvss import parse_vector
from ..ecosystems import get_adapter
from ..ecosystems.base import Dependency
from ..util import retry_with_backoff
from .github import GithubClient, RawAlert
from .osv import OsvClient

log = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_BATCH_SIZE = 500
_MAX_MANIFEST_BYTES = 4_000_000

MANIFESTS: dict[str, str] = {
    "go.mod": "go",
    "requirements.txt": "pip",
    "package-lock.json": "npm",
    "Cargo.lock": "cargo",
}

OSV_ECOSYSTEMS: dict[str, str] = {
    "go": "Go",
    "pip": "PyPI",
    "npm": "npm",
    "cargo": "crates.io",
    "maven": "Maven",
}

_SKIP_DIRS = frozenset({".git", "node_modules", "vendor", "target", ".venv", "testdata"})
_KNOWN_SEVERITIES = frozenset({"none", "low", "moderate", "medium", "high", "critical"})


@dataclass
class DiscoveredDependency:
    dependency: Dependency
    ecosystem: str
    manifest_path: str


@dataclass
class ScanStats:
    manifests: int = 0
    dependencies: int = 0
    unpinned_skipped: int = 0
    queried: int = 0
    advisories: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifests": self.manifests,
            "dependencies": self.dependencies,
            "unpinned_skipped": self.unpinned_skipped,
            "queried": self.queried,
            "advisories": self.advisories,
            "errors": self.errors,
        }


class OsvAlertSource:
    """Drop-in replacement for the Dependabot alert path.

    Delegates commit, tree and file access to the GitHub client so `structure_hash` and
    cache replay behave identically; only the alert list comes from a different place.
    """

    def __init__(
        self,
        github: GithubClient,
        checkout_root: Path,
        *,
        osv: OsvClient | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.github = github
        self.checkout_root = checkout_root
        self.osv = osv or OsvClient(checkout_root.parent / "cache")
        self._client = client or httpx.Client(timeout=60.0)
        self.stats = ScanStats()

    def close(self) -> None:
        self._client.close()
        self.github.close()

    def default_branch_sha(self, repo: str) -> str:
        return self.github.default_branch_sha(repo)

    def structure_hash(self, repo: str, sha: str, patterns: tuple[str, ...]) -> str:
        return self.github.structure_hash(repo, sha, patterns)

    def file_text(self, repo: str, path: str, ref: str) -> str | None:
        return self.github.file_text(repo, path, ref)

    def iter_alerts(self, repo: str) -> Iterator[RawAlert]:
        discovered = list(discover_dependencies(self.checkout_root, self.stats))
        if not discovered:
            log.warning("no pinned dependencies found under %s", self.checkout_root)
            return

        matches = self._query(discovered)
        number = 0
        for found, vuln_ids in matches:
            for vuln_id in vuln_ids:
                advisory = self._advisory(vuln_id)
                if advisory is None:
                    continue
                number += 1
                self.stats.advisories += 1
                yield _to_raw_alert(repo, found, advisory, number)

    def _query(
        self, discovered: list[DiscoveredDependency]
    ) -> list[tuple[DiscoveredDependency, list[str]]]:
        """Batch-query OSV. A failed batch yields nothing rather than a false all-clear."""
        out: list[tuple[DiscoveredDependency, list[str]]] = []
        for start in range(0, len(discovered), _BATCH_SIZE):
            chunk = discovered[start : start + _BATCH_SIZE]
            queries = [
                {
                    "package": {
                        "name": item.dependency.name,
                        "ecosystem": OSV_ECOSYSTEMS[item.ecosystem],
                    },
                    "version": item.dependency.version.lstrip("v"),
                }
                for item in chunk
            ]
            self.stats.queried += len(queries)

            def once(queries: list[dict[str, Any]] = queries) -> httpx.Response:
                return self._client.post(OSV_BATCH_URL, json={"queries": queries})

            try:
                response = retry_with_backoff(once, retry_on=(httpx.TransportError,))
            except Exception as exc:
                self.stats.errors.append(f"OSV batch query failed: {exc}")
                continue
            if response.status_code >= 400:
                self.stats.errors.append(f"OSV batch query: HTTP {response.status_code}")
                continue

            for item, result in zip(chunk, response.json().get("results") or [], strict=False):
                ids = [str(v["id"]) for v in result.get("vulns") or [] if v.get("id")]
                if ids:
                    out.append((item, ids))
        return out

    def _advisory(self, vuln_id: str) -> Any:
        try:
            return self.osv.fetch(vuln_id)
        except Exception as exc:
            self.stats.errors.append(f"advisory fetch failed for {vuln_id}: {exc}")
            return None


def discover_dependencies(root: Path, stats: ScanStats) -> Iterator[DiscoveredDependency]:
    """Walk a checkout for recognised manifests and read their pinned dependencies."""
    if not root.is_dir():
        return

    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        ecosystem = MANIFESTS.get(path.name)
        if ecosystem is None:
            continue
        adapter = get_adapter(ecosystem)
        if adapter is None:
            continue
        try:
            if path.stat().st_size > _MAX_MANIFEST_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        stats.manifests += 1
        relative = str(path.relative_to(root))
        for dependency in adapter.parse_dependencies(text):
            stats.dependencies += 1
            if not dependency.is_pinned:
                stats.unpinned_skipped += 1
                continue
            yield DiscoveredDependency(
                dependency=dependency, ecosystem=ecosystem, manifest_path=relative
            )


def _to_raw_alert(repo: str, found: DiscoveredDependency, advisory: Any, number: int) -> RawAlert:
    severity, score, vector = _severity(advisory.raw)
    ghsa = advisory.ghsa_id
    if not ghsa.startswith("GHSA-"):
        ghsa = next((a for a in advisory.aliases if a.startswith("GHSA-")), ghsa)

    return RawAlert(
        repo=repo,
        number=number,
        state="open",
        created_at=str(advisory.published or advisory.modified or ""),
        manifest_path=found.manifest_path,
        requirements=f"= {found.dependency.version}",
        scope_hint=found.dependency.scope,
        ghsa_id=ghsa,
        cve_id=advisory.cve_id,
        package_name=found.dependency.name,
        ecosystem=found.ecosystem,
        patched_version=_first_patched(advisory.raw, found.dependency.name),
        vulnerable_range=None,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        summary=advisory.summary,
    )


def _severity(raw: dict[str, Any]) -> tuple[str | None, float | None, str | None]:
    """Severity, numeric score and vector.

    OSV records a CVSS vector far more often than a numeric score, and the score is what
    the severity thresholds and the KEV rule compare against, so it is derived from the
    vector rather than left unset.
    """
    for entry in raw.get("severity") or []:
        if str(entry.get("type", "")).startswith("CVSS"):
            vector = str(entry.get("score") or "")
            parsed = parse_vector(vector)
            if parsed is not None:
                return (parsed.severity, parsed.base, parsed.vector)
            return (None, None, vector or None)

    database = raw.get("database_specific") or {}
    severity = database.get("severity")
    label = str(severity).lower() if severity else None
    return (label if label in _KNOWN_SEVERITIES else None, None, None)


def _first_patched(raw: dict[str, Any], package: str) -> str | None:
    """The first `fixed` event OSV records for this package."""
    for affected in raw.get("affected") or []:
        if (affected.get("package") or {}).get("name") != package:
            continue
        for ranges in affected.get("ranges") or []:
            for event in ranges.get("events") or []:
                if event.get("fixed"):
                    return str(event["fixed"])
    return None
