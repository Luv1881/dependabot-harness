"""Stage 1 — Ingest. Deterministic, zero tokens.

Per §5, for each Dependabot alert:
  1. compute ``alert_key``
  2. enrich from OSV.dev (affected symbols — what makes symbol-level reachability possible)
  3. enrich with EPSS and CISA KEV
  4. resolve ``is_direct`` / ``dep_scope`` from the manifest, not the Dependabot payload
  5. upsert; if a cached verdict is still fresh and ``structure_hash`` is unchanged, mark
     the alert skipped with reason ``cache_replay`` and copy the prior verdict forward

Checkpoint metric: **cache replay rate**. It must climb run over run. If it doesn't,
``alert_key`` is wrong.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from ..config import HarnessConfig
from ..db import AlertRecord, Database
from ..ecosystems import get_adapter
from ..schemas import validate
from ..sources import AlertSource
from ..sources.epss import EpssClient
from ..sources.github import GithubClient, RawAlert
from ..sources.kev import KevClient
from ..sources.osv import OsvClient
from ..util import age_days, utcnow
from ..util import alert_key as compute_alert_key

log = logging.getLogger(__name__)

STAGE = "ingest"


@dataclass
class RepoIngestResult:
    repo: str
    commit_sha: str
    structure_hash: str
    structure_changed: bool
    total: int = 0
    ingested: int = 0
    replayed: int = 0
    failed: int = 0
    unsupported_ecosystem: int = 0

    @property
    def cache_replay_rate(self) -> float:
        return self.replayed / self.total if self.total else 0.0


@dataclass
class IngestReport:
    run_id: str
    repos: list[RepoIngestResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(r.total for r in self.repos)

    @property
    def replayed(self) -> int:
        return sum(r.replayed for r in self.repos)

    @property
    def ingested(self) -> int:
        return sum(r.ingested for r in self.repos)

    @property
    def failed(self) -> int:
        return sum(r.failed for r in self.repos)

    @property
    def cache_replay_rate(self) -> float:
        return self.replayed / self.total if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "total_alerts": self.total,
            "ingested": self.ingested,
            "replayed": self.replayed,
            "failed": self.failed,
            "cache_replay_rate": round(self.cache_replay_rate, 4),
            "repos": [asdict(r) for r in self.repos],
        }


class IngestStage:
    """Holds the clients so a run reuses connections and warm caches across repos."""

    def __init__(
        self,
        cfg: HarnessConfig,
        db: Database,
        *,
        github: AlertSource | None = None,
        osv: OsvClient | None = None,
        epss: EpssClient | None = None,
        kev: KevClient | None = None,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.github: AlertSource = github or GithubClient(cfg.github)
        self.osv = osv or OsvClient(cfg.cache.dir)
        self.epss = epss or EpssClient(cfg.cache.dir)
        self.kev = kev or KevClient(cfg.cache.dir)
        self._manifest_cache: dict[tuple[str, str, str], str | None] = {}

    def close(self) -> None:
        for client in (self.github, self.osv, self.epss, self.kev):
            close = getattr(client, "close", None)
            if callable(close):
                close()


    def run(self, run_id: str) -> IngestReport:
        report = IngestReport(run_id=run_id)
        for repo in self.cfg.github.repos:
            report.repos.append(self.run_repo(run_id, repo))
        return report

    def run_repo(self, run_id: str, repo: str) -> RepoIngestResult:
        commit_sha = self.github.default_branch_sha(repo)
        structure_hash = self.github.structure_hash(
            repo, commit_sha, self.cfg.cache.invalidate_architecture_on_paths
        )
        previous = self.db.last_structure_hash(repo, before_commit=commit_sha)
        structure_changed = previous is not None and previous != structure_hash
        self.db.record_snapshot(repo, commit_sha, structure_hash)

        result = RepoIngestResult(
            repo=repo,
            commit_sha=commit_sha,
            structure_hash=structure_hash,
            structure_changed=structure_changed,
        )

        for raw in self.github.iter_alerts(repo):
            result.total += 1
            try:
                self._ingest_one(run_id, raw, commit_sha, structure_hash, result)
            except Exception as exc:
                result.failed += 1
                key = compute_alert_key(
                    ghsa_id=raw.ghsa_id,
                    purl=_purl(raw),
                    resolved_version=_resolved_version(raw),
                    manifest_path=raw.manifest_path,
                    repo=raw.repo,
                )
                log.warning("ingest failed for %s %s: %s", repo, raw.ghsa_id, exc)
                self.db.record_stage(
                    run_id=run_id,
                    alert_key=key,
                    stage=STAGE,
                    status="failed",
                    error=f"{type(exc).__name__}: {exc}",
                )
        return result


    def _ingest_one(
        self,
        run_id: str,
        raw: RawAlert,
        commit_sha: str,
        structure_hash: str,
        result: RepoIngestResult,
    ) -> None:
        purl = _purl(raw)
        resolved = _resolved_version(raw)
        key = compute_alert_key(
            ghsa_id=raw.ghsa_id,
            purl=purl,
            resolved_version=resolved,
            manifest_path=raw.manifest_path,
            repo=raw.repo,
        )

        if self.db.is_stage_complete(run_id, key, STAGE):
            prior = self.db.stage_payload(run_id, key, STAGE) or {}
            if prior.get("reason") == "cache_replay":
                result.replayed += 1
            else:
                result.ingested += 1
            return

        adapter = get_adapter(raw.ecosystem)
        if adapter is None:
            result.unsupported_ecosystem += 1

        advisory = self.osv.fetch(raw.ghsa_id)
        symbols = list(advisory.symbols) if advisory else None
        cve_id = raw.cve_id or (advisory.cve_id if advisory else None)

        epss_score = self.epss.score(cve_id) if cve_id else None
        in_kev = self.kev.contains(cve_id)

        scope = self._resolve_scope(raw, commit_sha)

        existing = self.db.get_alert(key)
        record = AlertRecord(
            alert_key=key,
            repo=raw.repo,
            ghsa_id=raw.ghsa_id,
            cve_id=cve_id,
            purl=purl,
            ecosystem=raw.ecosystem,
            resolved_ver=resolved,
            patched_ver=raw.patched_version,
            manifest_path=raw.manifest_path,
            dep_scope=scope.scope,
            is_direct=scope.is_direct,
            cvss_score=raw.cvss_score,
            cvss_vector=raw.cvss_vector,
            severity=raw.severity,
            epss_score=epss_score,
            in_kev=in_kev,
            gh_alert_num=raw.number,
            first_seen_at=existing.first_seen_at if existing else raw.created_at,
            last_seen_at=utcnow(),
            state=raw.state,
            symbols=symbols,
        )
        validate("alert", _for_schema(record))

        replay = self._cache_replay_candidate(record, structure_hash)

        with self.db.transaction():
            self.db.upsert_alert(record)
            if replay is not None:
                self.db.put_verdict(
                    alert_key=key,
                    run_id=run_id,
                    verdict=replay["verdict"],
                    validated=replay["validated"],
                    validator_notes=replay["validator_notes"],
                    structure_hash=structure_hash,
                )
                self.db.record_stage(
                    run_id=run_id,
                    alert_key=key,
                    stage=STAGE,
                    status="skipped",
                    payload={
                        "reason": "cache_replay",
                        "source_run_id": replay["run_id"],
                        "verdict_age_days": round(age_days(replay["created_at"]), 2),
                        "structure_hash": structure_hash,
                        "scope_source": scope.source,
                    },
                )
            else:
                self.db.record_stage(
                    run_id=run_id,
                    alert_key=key,
                    stage=STAGE,
                    status="done",
                    payload={
                        "reason": "ingested",
                        "structure_hash": structure_hash,
                        "commit_sha": commit_sha,
                        "symbols_known": bool(symbols),
                        "scope_source": scope.source,
                        "ecosystem_supported": adapter is not None,
                    },
                )

        if replay is not None:
            result.replayed += 1
        else:
            result.ingested += 1


    def _cache_replay_candidate(
        self, record: AlertRecord, structure_hash: str
    ) -> dict[str, Any] | None:
        """§5.5 — replay iff a fresh verdict exists AND the repo structure is unchanged.

        Both conditions matter: a fresh verdict against a changed dependency surface is
        not evidence about the current tree.
        """
        prior = self.db.latest_verdict(record.alert_key)
        if prior is None:
            return None
        if age_days(prior["created_at"]) > self.cfg.cache.verdict_ttl_days:
            return None
        if prior.get("structure_hash") != structure_hash:
            return None
        return prior

    def _resolve_scope(self, raw: RawAlert, commit_sha: str) -> Any:
        from ..ecosystems.base import Scope, ScopeResult

        adapter = get_adapter(raw.ecosystem)
        if adapter is None or not raw.manifest_path:
            return ScopeResult(Scope.UNKNOWN, None, "unsupported-ecosystem")
        text = self._manifest(raw.repo, raw.manifest_path, commit_sha)
        if text is None:
            return ScopeResult(Scope.UNKNOWN, None, "manifest-unreadable")
        return adapter.resolve_scope(text, raw.package_name)

    def _manifest(self, repo: str, path: str, ref: str) -> str | None:
        cache_key = (repo, path, ref)
        if cache_key not in self._manifest_cache:
            self._manifest_cache[cache_key] = self.github.file_text(repo, path, ref)
        return self._manifest_cache[cache_key]


def _purl(raw: RawAlert) -> str:
    """Package URL. `pkg:<type>/<name>` — the identifier OpenVEX uses as product id."""
    eco = {"gomod": "golang", "go": "golang", "pip": "pypi", "rust": "cargo"}.get(
        raw.ecosystem, raw.ecosystem
    )
    name = raw.package_name.replace(":", "/") if eco == "maven" else raw.package_name
    return f"pkg:{eco}/{name}"


def _resolved_version(raw: RawAlert) -> str | None:
    """Best available currently-installed version.

    GraphQL gives `vulnerableRequirements` like `= 1.2.3`; anything looser is not a
    resolved version and stays None rather than being guessed at.
    """
    req = (raw.requirements or "").strip()
    if req.startswith("= "):
        return req[2:].strip()
    if req.startswith("="):
        return req[1:].strip()
    return None


def _for_schema(record: AlertRecord) -> dict[str, Any]:
    data = asdict(record)
    return data
