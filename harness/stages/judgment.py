"""Stage 6 — Judgment. Agent, the expensive stage.

Input is the evidence bundle plus the cached architecture document. Nothing else: the
agent does not choose what to look at first, and it cannot read the repository except
through a capped tool surface.

Hitting the tool cap produces `could_not_determine`. That is a correct answer, not a
failure, and the pipeline is built to carry it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..agents import TOOL_DEFINITIONS, Toolbox, run_agent_loop
from ..config import HarnessConfig
from ..db import AlertRecord, Database
from ..models import BudgetLedger, ModelClient, ModelError, ModelRequest
from ..models.client import ContextCeilingExceeded
from ..schemas import SchemaViolation, validate
from ..sources.checkout import CheckoutError, CheckoutManager
from ..sources.osv import OsvClient
from ..util import RetryExhausted, canonical_json

log = logging.getLogger(__name__)

STAGE = "judgment"
ROLE = "judgment"

_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "judgment.md"


@dataclass
class JudgmentReport:
    run_id: str
    judged: int = 0
    undetermined: int = 0
    deferred: int = 0
    failed: int = 0
    cap_reached: int = 0
    verdicts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "judged": self.judged,
            "undetermined": self.undetermined,
            "deferred": self.deferred,
            "failed": self.failed,
            "cap_reached": self.cap_reached,
            "verdicts": self.verdicts,
        }


def undetermined_verdict(
    alert: AlertRecord, reason: str, *, unknowns: list[str] | None = None, tool_calls: int = 0
) -> dict[str, Any]:
    """The honest answer when the evidence does not support a conclusion."""
    return {
        "alert_key": alert.alert_key,
        "threat_model": {
            "attacker": "undetermined",
            "boundary_crossed": "undetermined",
            "assumption_broken": "undetermined",
            "preconditions": [],
        },
        "verdict": "could_not_determine",
        "vex_status": "under_investigation",
        "vex_justification": None,
        "reachability_confirmed": False,
        "confidence": 0.0,
        "production_reachable": None,
        "severity_adjusted": alert.severity,
        "severity_rationale": reason,
        "evidence_cited": [],
        "recommended_action": "human review required",
        "owner_hint": None,
        "unknowns": unknowns or [reason],
        "needs_human": True,
        "decided_by": "judgment",
        "tool_calls_used": tool_calls,
    }


class JudgmentStage:
    def __init__(
        self,
        cfg: HarnessConfig,
        db: Database,
        ledger: BudgetLedger,
        *,
        client: ModelClient | None = None,
        checkouts: CheckoutManager | None = None,
        osv: OsvClient | None = None,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.ledger = ledger
        self.client = client or ModelClient(cfg.model(ROLE), ledger)
        self.checkouts = checkouts or CheckoutManager(cfg.storage.checkout_dir, cfg.github)
        self.osv = osv or OsvClient(cfg.cache.dir)
        self.prompt = _PROMPT_PATH.read_text()
        self.max_tool_calls = cfg.budgets.judgment_max_tool_calls

    def run(self, run_id: str) -> JudgmentReport:
        report = JudgmentReport(run_id=run_id)
        for repo in self.cfg.github.repos:
            self.run_repo(run_id, repo, report)
        return report

    def run_repo(self, run_id: str, repo: str, report: JudgmentReport) -> None:
        pending = [a for a in self.db.alerts_for_repo(repo) if self._needs_judgment(run_id, a)]
        if not pending:
            return

        checkout_path = self._checkout(repo)
        architecture = self._architecture(repo)

        for alert in pending:
            decision = self.ledger.check(repo=repo, alert_key=alert.alert_key)
            if not decision.allowed:
                report.deferred += 1
                self.db.record_stage(
                    run_id=run_id,
                    alert_key=alert.alert_key,
                    stage=STAGE,
                    status="budget_deferred",
                    payload={"scope": decision.scope, "spent": decision.spent},
                )
                continue

            bundle = self.db.stage_payload(run_id, alert.alert_key, "evidence")
            if bundle is None:
                report.failed += 1
                self.db.record_stage(
                    run_id=run_id,
                    alert_key=alert.alert_key,
                    stage=STAGE,
                    status="failed",
                    error="no evidence bundle recorded",
                )
                continue

            verdict, status = self._judge(run_id, repo, alert, bundle, architecture, checkout_path)
            self._record(run_id, repo, alert, verdict, status, report)

    def _judge(
        self,
        run_id: str,
        repo: str,
        alert: AlertRecord,
        bundle: dict[str, Any],
        architecture: dict[str, Any] | None,
        checkout_path: Path | None,
    ) -> tuple[dict[str, Any], str]:
        toolbox = Toolbox(repo_root=checkout_path, osv=self.osv, max_calls=self.max_tool_calls)
        request = ModelRequest(
            system=self.prompt,
            user=self._assemble(alert, bundle, architecture),
            max_tokens=8_000,
            cacheable_prefix=self.prompt,
            tools=TOOL_DEFINITIONS,
        )

        try:
            loop = run_agent_loop(
                self.client,
                request,
                toolbox,
                repo=repo,
                stage=STAGE,
                alert_key=alert.alert_key,
            )
        except ContextCeilingExceeded as exc:
            return undetermined_verdict(
                alert, f"context assembly exceeded the ceiling: {exc}"
            ), "failed"
        except (ModelError, RetryExhausted) as exc:
            log.warning("judgment failed for %s: %s", alert.alert_key, exc)
            return undetermined_verdict(alert, f"model call failed: {exc}"), "failed"

        if loop.cap_reached:
            return (
                undetermined_verdict(
                    alert,
                    f"exhausted the {self.max_tool_calls}-call tool budget without reaching a "
                    "conclusion",
                    tool_calls=toolbox.used,
                ),
                "done",
            )

        try:
            verdict = loop.response.json()
        except ModelError as exc:
            return undetermined_verdict(alert, f"unparsable verdict: {exc}"), "failed"

        verdict["alert_key"] = alert.alert_key
        verdict.setdefault("decided_by", "judgment")
        verdict["tool_calls_used"] = toolbox.used
        if toolbox.audit():
            verdict["tool_audit"] = toolbox.audit()

        try:
            validate("verdict", verdict)
        except SchemaViolation as exc:
            return undetermined_verdict(alert, f"verdict failed schema validation: {exc}"), "failed"

        return verdict, "done"

    def _assemble(
        self,
        alert: AlertRecord,
        bundle: dict[str, Any],
        architecture: dict[str, Any] | None,
    ) -> str:
        """Deterministic context. The agent is handed facts, not a repository."""
        sections = [
            "## Evidence bundle",
            "```json",
            canonical_json(bundle),
            "```",
            "",
            "## Repository architecture",
            "```json",
            canonical_json(architecture) if architecture else "null",
            "```",
            "",
            "## Alert",
            "```json",
            canonical_json(
                {
                    "alert_key": alert.alert_key,
                    "repo": alert.repo,
                    "ghsa_id": alert.ghsa_id,
                    "cve_id": alert.cve_id,
                    "purl": alert.purl,
                    "manifest_path": alert.manifest_path,
                    "resolved_version": alert.resolved_ver,
                    "patched_version": alert.patched_ver,
                    "dep_scope": alert.dep_scope,
                    "is_direct": alert.is_direct,
                }
            ),
            "```",
            "",
            f"You may make at most {self.max_tool_calls} tool calls.",
        ]
        if architecture is None:
            sections.append(
                "No architecture document is cached for this repository. Treat deployment "
                "and exposure as unknown rather than assuming them."
            )
        return "\n".join(sections)

    def _needs_judgment(self, run_id: str, alert: AlertRecord) -> bool:
        if self.db.is_stage_complete(run_id, alert.alert_key, STAGE):
            return False
        return self.db.stage_status(run_id, alert.alert_key, "evidence") == "done"

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
            log.warning("judgment checkout unavailable for %s: %s", repo, exc)
            return None

    def _architecture(self, repo: str) -> dict[str, Any] | None:
        snapshot = self.db.query(
            "SELECT structure_hash FROM repo_snapshots WHERE repo=? "
            "ORDER BY seen_at DESC, rowid DESC LIMIT 1",
            (repo,),
        )
        if not snapshot:
            return None
        cached = self.db.get_architecture(repo, str(snapshot[0]["structure_hash"]))
        return cached["content"] if cached else None

    def _record(
        self,
        run_id: str,
        repo: str,
        alert: AlertRecord,
        verdict: dict[str, Any],
        status: str,
        report: JudgmentReport,
    ) -> None:
        name = str(verdict.get("verdict", "could_not_determine"))
        report.verdicts[name] = report.verdicts.get(name, 0) + 1
        if name == "could_not_determine":
            report.undetermined += 1
            if "tool budget" in str(verdict.get("severity_rationale", "")):
                report.cap_reached += 1
        if status == "failed":
            report.failed += 1
        else:
            report.judged += 1

        structure_hash = self.db.last_structure_hash(repo)
        with self.db.transaction():
            self.db.record_stage(
                run_id=run_id,
                alert_key=alert.alert_key,
                stage=STAGE,
                status=status,
                payload={"verdict": name, "tool_calls_used": verdict.get("tool_calls_used", 0)},
            )
            self.db.put_verdict(
                alert_key=alert.alert_key,
                run_id=run_id,
                verdict=verdict,
                structure_hash=structure_hash,
            )
