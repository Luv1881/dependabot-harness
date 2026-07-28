"""Stage 7 — Validation. Mechanical checks, then an adversarial agent.

The validator runs on a different model from judgment, enforced at startup. Its response
schema contains only `agrees`, `strongest_objection` and `cited_counter_evidence`, with
`additionalProperties: false`, so it has no structural ability to file a finding of its
own. That constraint lives in the schema, not in the prompt.

Disputed verdicts go to a human queue. They are never resolved by asking a third model.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import HarnessConfig
from ..db import AlertRecord, Database
from ..models import BudgetLedger, ModelClient, ModelError, ModelRequest
from ..models.client import ContextCeilingExceeded
from ..schemas import SchemaViolation
from ..schemas import validate as validate_schema
from ..sources.checkout import CheckoutError, CheckoutManager
from ..util import RetryExhausted, canonical_json
from ..validation.mechanical import MechanicalReport, check_verdict

log = logging.getLogger(__name__)

STAGE = "validate"
ROLE = "validator"

_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "validator.md"


@dataclass
class ValidationReport:
    run_id: str
    checked: int = 0
    mechanically_rejected: int = 0
    agreed: int = 0
    disputed: int = 0
    validator_unavailable: int = 0
    human_queue: list[str] = field(default_factory=list)

    @property
    def disagreement_rate(self) -> float:
        judged = self.agreed + self.disputed
        return self.disputed / judged if judged else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "checked": self.checked,
            "mechanically_rejected": self.mechanically_rejected,
            "agreed": self.agreed,
            "disputed": self.disputed,
            "validator_unavailable": self.validator_unavailable,
            "disagreement_rate": round(self.disagreement_rate, 4),
            "human_queue": self.human_queue,
        }


class ValidationStage:
    def __init__(
        self,
        cfg: HarnessConfig,
        db: Database,
        ledger: BudgetLedger,
        *,
        client: ModelClient | None = None,
        checkouts: CheckoutManager | None = None,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.ledger = ledger
        self.client = client or ModelClient(cfg.model(ROLE), ledger)
        self.checkouts = checkouts or CheckoutManager(cfg.storage.checkout_dir, cfg.github)
        self.prompt = _PROMPT_PATH.read_text()
        self._assert_divergence()

    def _assert_divergence(self) -> None:
        """Nothing grades its own homework. Fail here, not silently mid-run."""
        judgment = self.cfg.model("judgment")
        validator = self.cfg.model(ROLE)
        if judgment.identity == validator.identity:
            raise ValueError(
                "validator model must differ from judgment model; both are "
                f"{judgment.provider}/{judgment.model}"
            )

    def run(self, run_id: str) -> ValidationReport:
        report = ValidationReport(run_id=run_id)
        for repo in self.cfg.github.repos:
            self.run_repo(run_id, repo, report)
        return report

    def run_repo(self, run_id: str, repo: str, report: ValidationReport) -> None:
        pending = [a for a in self.db.alerts_for_repo(repo) if self._needs_validation(run_id, a)]
        if not pending:
            return
        checkout_path = self._checkout(repo)

        for alert in pending:
            stored = self.db.latest_verdict(alert.alert_key)
            if stored is None:
                continue
            verdict = stored["verdict"]
            structure_hash = stored["structure_hash"]
            bundle = self.db.stage_payload(run_id, alert.alert_key, "evidence")
            report.checked += 1

            mechanical = check_verdict(
                verdict, bundle=bundle, repo_root=checkout_path, ecosystem=alert.ecosystem
            )
            if not mechanical.passed:
                report.mechanically_rejected += 1
                report.human_queue.append(alert.alert_key)
                self._record(
                    run_id,
                    alert,
                    verdict=verdict,
                    structure_hash=structure_hash,
                    status="failed",
                    payload={"mechanical": mechanical.to_dict(), "adversarial": None},
                    validated=False,
                    notes=_summarize(mechanical),
                )
                continue

            adversarial = self._adversarial(repo, alert, verdict, bundle)
            self._settle(run_id, alert, verdict, structure_hash, mechanical, adversarial, report)

    def _adversarial(
        self,
        repo: str,
        alert: AlertRecord,
        verdict: dict[str, Any],
        bundle: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        decision = self.ledger.check(repo=repo, alert_key=alert.alert_key)
        if not decision.allowed:
            return None

        request = ModelRequest(
            system=self.prompt,
            user=(
                "## Evidence bundle\n```json\n"
                f"{canonical_json(bundle)}\n```\n\n"
                "## Verdict under review\n```json\n"
                f"{canonical_json(verdict)}\n```"
            ),
            max_tokens=4_000,
            cacheable_prefix=self.prompt,
        )
        try:
            response = self.client.complete(
                request, repo=repo, stage=STAGE, alert_key=alert.alert_key
            )
            payload: dict[str, Any] = response.json()
            validate_schema("validator_response", payload)
        except (ModelError, RetryExhausted, ContextCeilingExceeded, SchemaViolation) as exc:
            log.warning("validator unavailable for %s: %s", alert.alert_key, exc)
            return None
        return payload

    def _settle(
        self,
        run_id: str,
        alert: AlertRecord,
        verdict: dict[str, Any],
        structure_hash: str | None,
        mechanical: MechanicalReport,
        adversarial: dict[str, Any] | None,
        report: ValidationReport,
    ) -> None:
        if adversarial is None:
            report.validator_unavailable += 1
            report.human_queue.append(alert.alert_key)
            self._record(
                run_id,
                alert,
                verdict=verdict,
                structure_hash=structure_hash,
                status="done",
                payload={"mechanical": mechanical.to_dict(), "adversarial": None},
                validated=None,
                notes="validator unavailable; verdict is unconfirmed",
            )
            return

        agrees = bool(adversarial.get("agrees"))
        if agrees:
            report.agreed += 1
        else:
            report.disputed += 1
            report.human_queue.append(alert.alert_key)

        self._record(
            run_id,
            alert,
            verdict=verdict,
            structure_hash=structure_hash,
            status="done",
            payload={"mechanical": mechanical.to_dict(), "adversarial": adversarial},
            validated=agrees,
            notes=str(adversarial.get("strongest_objection") or ""),
        )

    def _record(
        self,
        run_id: str,
        alert: AlertRecord,
        *,
        verdict: dict[str, Any],
        structure_hash: str | None,
        status: str,
        payload: dict[str, Any],
        validated: bool | None,
        notes: str,
    ) -> None:
        """The verdict is passed through, never re-read.

        Re-reading would open a window in which a concurrent write is clobbered, and a
        missing row would silently overwrite a real verdict with an empty object.
        """
        with self.db.transaction():
            self.db.record_stage(
                run_id=run_id,
                alert_key=alert.alert_key,
                stage=STAGE,
                status=status,
                payload=payload,
            )
            self.db.put_verdict(
                alert_key=alert.alert_key,
                run_id=run_id,
                verdict=verdict,
                validated=validated,
                validator_notes=notes,
                structure_hash=structure_hash,
            )

    def _needs_validation(self, run_id: str, alert: AlertRecord) -> bool:
        if self.db.is_stage_complete(run_id, alert.alert_key, STAGE):
            return False
        return self.db.stage_status(run_id, alert.alert_key, "judgment") == "done"

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
        except CheckoutError:
            return None


def _summarize(mechanical: MechanicalReport) -> str:
    return "; ".join(f"{f.check}: {f.detail}" for f in mechanical.failures)
