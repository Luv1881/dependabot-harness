"""Stage 2 — deterministic policy rules. Zero tokens.

Applied before any model is touched. Each terminating rule writes a verdict and a
machine-readable reason; every remaining alert flows on to the expensive stages.

Checkpoint metric: the percentage of the real backlog each rule clears. That number
decides whether the expensive stages are worth running at all.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ..config import HarnessConfig
from ..db import AlertRecord, Database
from ..policy import ClearanceStats, PolicyEngine, RepoFactsProvider, RuleContext, RuleOutcome
from ..policy.context import OutcomeKind
from ..sources.checkout import CheckoutError, CheckoutManager

log = logging.getLogger(__name__)

STAGE = "policy"


@dataclass
class PolicyReport:
    run_id: str
    stats: ClearanceStats
    checkout_failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = self.stats.to_dict()
        payload["run_id"] = self.run_id
        payload["checkout_failures"] = self.checkout_failures
        return payload


class PolicyStage:
    def __init__(
        self,
        cfg: HarnessConfig,
        db: Database,
        engine: PolicyEngine,
        *,
        checkouts: CheckoutManager | None = None,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.engine = engine
        self.checkouts = checkouts or CheckoutManager(cfg.storage.checkout_dir, cfg.github)

    def run(self, run_id: str) -> PolicyReport:
        self.engine.reset_stats()
        report = PolicyReport(run_id=run_id, stats=self.engine.stats)
        for repo in self.cfg.github.repos:
            self.run_repo(run_id, repo, report)
        return report

    def run_repo(self, run_id: str, repo: str, report: PolicyReport) -> None:
        alerts = [a for a in self.db.alerts_for_repo(repo) if self._needs_policy(run_id, a)]
        if not alerts:
            return
        facts = self._facts_for(repo, report)
        for alert in alerts:
            ctx = RuleContext(alert=alert, facts=facts, thresholds=self.engine.thresholds)
            outcome = self.engine.evaluate(ctx)
            self._record(run_id, alert, outcome, facts.structure_hash)

    def _needs_policy(self, run_id: str, alert: AlertRecord) -> bool:
        if self.db.is_stage_complete(run_id, alert.alert_key, STAGE):
            self._recount(run_id, alert)
            return False
        return self.db.is_stage_complete(run_id, alert.alert_key, "ingest")

    def _recount(self, run_id: str, alert: AlertRecord) -> None:
        payload = self.db.stage_payload(run_id, alert.alert_key, STAGE) or {}
        self.engine.stats.total += 1
        rule_id = payload.get("rule_id")
        if rule_id:
            self.engine.stats.by_rule[str(rule_id)] += 1

    def _facts_for(self, repo: str, report: PolicyReport) -> RepoFactsProvider:
        snapshot = self.db.query(
            "SELECT commit_sha, structure_hash FROM repo_snapshots WHERE repo=? "
            "ORDER BY seen_at DESC, rowid DESC LIMIT 1",
            (repo,),
        )
        commit_sha = str(snapshot[0]["commit_sha"]) if snapshot else None
        structure_hash = str(snapshot[0]["structure_hash"]) if snapshot else None

        checkout_path = None
        if commit_sha:
            try:
                checkout_path = self.checkouts.ensure(repo, commit_sha).path
            except CheckoutError as exc:
                log.warning("checkout unavailable for %s@%s: %s", repo, commit_sha, exc)
                report.checkout_failures.append(f"{repo}@{commit_sha}: {exc}")

        architecture = None
        if structure_hash:
            cached = self.db.get_architecture(repo, structure_hash)
            architecture = cached["content"] if cached else None

        return RepoFactsProvider(
            repo=repo,
            db=self.db,
            checkout_path=checkout_path,
            architecture=architecture,
            structure_hash=structure_hash,
        )

    def _record(
        self,
        run_id: str,
        alert: AlertRecord,
        outcome: RuleOutcome | None,
        structure_hash: str | None,
    ) -> None:
        if outcome is None:
            self.db.record_stage(
                run_id=run_id,
                alert_key=alert.alert_key,
                stage=STAGE,
                status="done",
                payload={"rule_id": None, "reason": "no_rule_matched"},
            )
            return

        with self.db.transaction():
            self.db.record_stage(
                run_id=run_id,
                alert_key=alert.alert_key,
                stage=STAGE,
                status="skipped",
                payload=outcome.to_dict(),
            )
            if outcome.kind is not OutcomeKind.DEDUP and outcome.verdict:
                self.db.put_verdict(
                    alert_key=alert.alert_key,
                    run_id=run_id,
                    verdict=self._verdict_document(alert, outcome),
                    structure_hash=structure_hash,
                )

    @staticmethod
    def _verdict_document(alert: AlertRecord, outcome: RuleOutcome) -> dict[str, Any]:
        return {
            "alert_key": alert.alert_key,
            "threat_model": {
                "attacker": "n/a - cleared by deterministic policy",
                "boundary_crossed": "n/a",
                "assumption_broken": "n/a",
                "preconditions": [],
            },
            "verdict": outcome.verdict,
            "vex_status": outcome.vex_status,
            "vex_justification": outcome.vex_justification,
            "reachability_confirmed": False,
            "confidence": 1.0,
            "production_reachable": outcome.verdict == "affected",
            "severity_adjusted": alert.severity,
            "severity_rationale": f"deterministic rule {outcome.rule_id}: {outcome.reason}",
            "evidence_cited": [],
            "recommended_action": _recommended_action(alert, outcome),
            "owner_hint": None,
            "unknowns": [],
            "needs_human": outcome.needs_human,
            "decided_by": "policy",
            "rule_id": outcome.rule_id,
            "rule_detail": outcome.detail,
        }


def _recommended_action(alert: AlertRecord, outcome: RuleOutcome) -> str:
    if outcome.verdict == "affected" and alert.patched_ver:
        return f"bump {alert.purl} to {alert.patched_ver}"
    if outcome.verdict == "fixed":
        return "no action: resolved version already at or above patched version"
    return "no action"
