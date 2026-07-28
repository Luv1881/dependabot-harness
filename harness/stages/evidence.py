"""Stage 5 — Evidence assembly. Deterministic, zero tokens.

Runs the real SCA tooling and records its output. The judgment agent receives this
bundle and never invokes a tool itself.

A repo whose evidence produced no reachable symbol across every alert is flagged
``shallow`` and requeued: a toolchain that dismisses everything in seconds is broken, not
a repo that happens to be secure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import HarnessConfig
from ..db import AlertRecord, Database
from ..ecosystems import get_adapter
from ..ecosystems.base import ReachabilityResult
from ..evidence import EvidenceBuilder, EvidenceBundle
from ..evidence.bundle import is_shallow
from ..schemas import validate
from ..sources.checkout import CheckoutError, CheckoutManager

log = logging.getLogger(__name__)

STAGE = "evidence"


@dataclass
class RepoEvidenceResult:
    repo: str
    analyzed: int = 0
    failed_toolchain: int = 0
    unsupported: int = 0
    shallow: bool = False


@dataclass
class EvidenceReport:
    run_id: str
    repos: list[RepoEvidenceResult] = field(default_factory=list)

    @property
    def analyzed(self) -> int:
        return sum(r.analyzed for r in self.repos)

    @property
    def failed_toolchain(self) -> int:
        return sum(r.failed_toolchain for r in self.repos)

    @property
    def shallow_repos(self) -> list[str]:
        return [r.repo for r in self.repos if r.shallow]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "analyzed": self.analyzed,
            "failed_toolchain": self.failed_toolchain,
            "shallow_repos": self.shallow_repos,
            "repos": [r.__dict__ for r in self.repos],
        }


class EvidenceStage:
    def __init__(
        self,
        cfg: HarnessConfig,
        db: Database,
        *,
        checkouts: CheckoutManager | None = None,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.checkouts = checkouts or CheckoutManager(cfg.storage.checkout_dir, cfg.github)

    def run(self, run_id: str) -> EvidenceReport:
        report = EvidenceReport(run_id=run_id)
        for repo in self.cfg.github.repos:
            report.repos.append(self.run_repo(run_id, repo))
        return report

    def run_repo(self, run_id: str, repo: str) -> RepoEvidenceResult:
        result = RepoEvidenceResult(repo=repo)
        pending = [a for a in self.db.alerts_for_repo(repo) if self._needs_evidence(run_id, a)]
        if not pending:
            return result

        checkout_path = self._checkout(repo)
        bundles: list[EvidenceBundle] = []

        for alert in pending:
            adapter = get_adapter(alert.ecosystem)
            if adapter is None:
                result.unsupported += 1
                self.db.record_stage(
                    run_id=run_id,
                    alert_key=alert.alert_key,
                    stage=STAGE,
                    status="failed",
                    error=f"no adapter for ecosystem {alert.ecosystem!r}",
                )
                continue

            reach = self._reachability(adapter, checkout_path, alert)
            bundle = EvidenceBuilder(adapter).build(
                alert, reach, repo_root=checkout_path, advisory_summary=""
            )
            validate("evidence_bundle", bundle.to_dict())
            bundles.append(bundle)

            if bundle.toolchain_failed:
                result.failed_toolchain += 1
            result.analyzed += 1
            self.db.record_stage(
                run_id=run_id,
                alert_key=alert.alert_key,
                stage=STAGE,
                status="done",
                payload=bundle.to_dict(),
            )

        result.shallow = is_shallow(bundles)
        if result.shallow:
            log.warning("repo %s produced no reachable evidence; flagged shallow", repo)
            self._requeue(run_id, pending)
        return result

    def _needs_evidence(self, run_id: str, alert: AlertRecord) -> bool:
        """Skips alerts a cluster already suppressed; they inherit a verdict instead."""
        if self.db.is_stage_complete(run_id, alert.alert_key, STAGE):
            return False
        if self.db.stage_status(run_id, alert.alert_key, "dedup") == "skipped":
            return False
        return self.db.stage_status(run_id, alert.alert_key, "policy") == "done"

    def _checkout(self, repo: str) -> Path | None:
        snapshot = self.db.query(
            "SELECT commit_sha FROM repo_snapshots WHERE repo=? ORDER BY seen_at DESC, rowid DESC "
            "LIMIT 1",
            (repo,),
        )
        if not snapshot:
            return None
        try:
            return self.checkouts.ensure(repo, str(snapshot[0]["commit_sha"])).path
        except CheckoutError as exc:
            log.warning("checkout unavailable for %s: %s", repo, exc)
            return None

    @staticmethod
    def _reachability(adapter: Any, checkout_path: Path | None, alert: AlertRecord) -> Any:
        if checkout_path is None:
            return ReachabilityResult.failed("checkout", "no checkout available")
        try:
            return adapter.reachability(checkout_path, alert)
        except NotImplementedError as exc:
            return ReachabilityResult.failed(adapter.ecosystem, f"not implemented: {exc}")
        except Exception as exc:
            return ReachabilityResult.failed(adapter.ecosystem, f"{type(exc).__name__}: {exc}")

    def _requeue(self, run_id: str, alerts: list[AlertRecord]) -> None:
        """Flag every alert in a shallow repo without discarding what was measured.

        The bundle already written says *why* the toolchain produced nothing, which is
        the whole diagnostic. Overwriting it with the shallow marker would leave an
        operator knowing only that something went wrong.
        """
        for alert in alerts:
            existing = self.db.stage_payload(run_id, alert.alert_key, STAGE) or {}
            reason = (existing.get("reachability") or {}).get("error") or "no reason recorded"
            self.db.record_stage(
                run_id=run_id,
                alert_key=alert.alert_key,
                stage=STAGE,
                status="failed",
                error=f"shallow: repo produced no reachable evidence across all alerts ({reason})",
            )
