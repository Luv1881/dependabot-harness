"""Stage 8 — Emit. Deterministic, zero tokens.

Writes OpenVEX and SARIF, renders the PR comment, and performs the only outward-facing
writes the harness is permitted: a PR comment, a SARIF upload, and a gated dismissal.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from ..config import HarnessConfig
from ..db import AlertRecord, Database
from ..emit import comment, openvex, sarif
from ..emit.dismissal import DISMISSED_REASON, DismissalGate, dismissal_comment
from ..sources import AlertDismisser
from ..sources.github import GithubError

log = logging.getLogger(__name__)

STAGE = "emit"


@dataclass
class RepoEmitResult:
    repo: str
    statements: int = 0
    findings: int = 0
    dismissed: int = 0
    dismissal_blocked: int = 0
    vex_path: str | None = None
    sarif_path: str | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class EmitReport:
    run_id: str
    repos: list[RepoEmitResult] = field(default_factory=list)

    @property
    def dismissed(self) -> int:
        return sum(r.dismissed for r in self.repos)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "dismissed": self.dismissed,
            "repos": [r.__dict__ for r in self.repos],
        }


class EmitStage:
    def __init__(
        self,
        cfg: HarnessConfig,
        db: Database,
        *,
        github: AlertDismisser | None = None,
        coverage_complete: bool = True,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.github = github
        self.gate = DismissalGate(
            enabled=cfg.output.auto_dismiss,
            requirements=dict(cfg.output.auto_dismiss_requires),
            coverage_complete=coverage_complete,
        )

    def run(self, run_id: str) -> EmitReport:
        report = EmitReport(run_id=run_id)
        for repo in self.cfg.github.repos:
            report.repos.append(self.run_repo(run_id, repo))
        return report

    def run_repo(self, run_id: str, repo: str) -> RepoEmitResult:
        result = RepoEmitResult(repo=repo)
        alerts = self.db.alerts_for_repo(repo)
        rows = [(a, self.db.latest_verdict(a.alert_key)) for a in alerts]
        decided = [(a, v) for a, v in rows if v is not None]
        if not decided:
            return result

        statements = []
        findings = []
        for alert, stored in decided:
            verdict = dict(stored["verdict"])
            verdict.setdefault("ghsa_id", alert.ghsa_id)
            verdict.setdefault("cve_id", alert.cve_id)
            verdict.setdefault("purl", alert.purl)

            statement = openvex.statement_from_verdict(verdict, alert.purl)
            if statement is not None:
                statements.append(statement)
            findings.append(self._finding(run_id, alert, verdict, stored))

        result.statements = len(statements)
        result.findings = len(findings)
        result.vex_path = self._write(
            self.cfg.output.vex_dir, repo, "vex.json", openvex.build_document(repo, statements)
        )
        result.sarif_path = self._write(
            self.cfg.output.sarif_dir, repo, "sarif.json", sarif.build_report(repo, findings)
        )

        for alert, stored in decided:
            self._maybe_dismiss(run_id, repo, alert, stored, result)

        return result

    def _finding(
        self,
        run_id: str,
        alert: AlertRecord,
        verdict: dict[str, Any],
        stored: dict[str, Any],
    ) -> dict[str, Any]:
        bundle = self.db.stage_payload(run_id, alert.alert_key, "evidence") or {}
        reachability = bundle.get("reachability") or {}
        return {
            "alert_key": alert.alert_key,
            "ghsa_id": alert.ghsa_id,
            "purl": alert.purl,
            "manifest_path": alert.manifest_path,
            "cvss": alert.cvss_score,
            "summary": (bundle.get("advisory") or {}).get("summary"),
            "verdict": verdict.get("verdict"),
            "vex_justification": verdict.get("vex_justification"),
            "severity_rationale": verdict.get("severity_rationale"),
            "recommended_action": verdict.get("recommended_action"),
            "evidence_cited": verdict.get("evidence_cited") or [],
            "unknowns": verdict.get("unknowns") or [],
            "needs_human": verdict.get("needs_human"),
            "decided_by": verdict.get("decided_by"),
            "reachability_level": reachability.get("level"),
            "reachability_confidence": reachability.get("confidence"),
            "analysis_method": reachability.get("method"),
            "validator_agreed": _tristate(stored.get("validated")),
        }

    def _maybe_dismiss(
        self,
        run_id: str,
        repo: str,
        alert: AlertRecord,
        stored: dict[str, Any],
        result: RepoEmitResult,
    ) -> None:
        if self._already_dismissed(alert.alert_key):
            result.dismissal_blocked += 1
            self.db.record_stage(
                run_id=run_id,
                alert_key=alert.alert_key,
                stage=STAGE,
                status="done",
                payload={"dismissed": False, "blocked_by": "already dismissed in an earlier run"},
            )
            return

        verdict = stored["verdict"]
        decision = self.gate.evaluate(verdict, _tristate(stored.get("validated")))
        if not decision.allowed:
            result.dismissal_blocked += 1
            self.db.record_stage(
                run_id=run_id,
                alert_key=alert.alert_key,
                stage=STAGE,
                status="done",
                payload={"dismissed": False, "blocked_by": decision.blocked_by},
            )
            return

        if self.github is None:
            result.errors.append("dismissal gated open but no GitHub client is configured")
            self.db.record_stage(
                run_id=run_id,
                alert_key=alert.alert_key,
                stage=STAGE,
                status="failed",
                error="no GitHub client configured; dismissal not attempted",
            )
            return

        try:
            self.github.dismiss_alert(
                repo,
                alert.gh_alert_num,
                reason=DISMISSED_REASON,
                comment=dismissal_comment(verdict),
            )
        except GithubError as exc:
            result.errors.append(f"dismissal failed for {alert.alert_key}: {exc}")
            self.db.record_stage(
                run_id=run_id,
                alert_key=alert.alert_key,
                stage=STAGE,
                status="failed",
                error=f"dismissal failed: {exc}",
            )
            return

        result.dismissed += 1
        self.db.record_stage(
            run_id=run_id,
            alert_key=alert.alert_key,
            stage=STAGE,
            status="done",
            payload={"dismissed": True, "justification": verdict.get("vex_justification")},
        )

    def _already_dismissed(self, alert_key: str) -> bool:
        """Whether any earlier run already dismissed this alert.

        Stage results are scoped to a run, so without this a second run would re-issue a
        dismissal for an alert it already closed.
        """
        rows = self.db.query(
            "SELECT payload_json FROM stage_results WHERE alert_key=? AND stage=? "
            "AND status='done'",
            (alert_key, STAGE),
        )
        for row in rows:
            payload = json.loads(row["payload_json"] or "{}")
            if payload.get("dismissed"):
                return True
        return False

    def render_pr_comment(self, run_id: str, repo: str, base_run_id: str | None) -> str:
        """Only the diff against the base branch's run. Never the full set."""
        head = self._verdict_map(run_id, repo)
        base = self._verdict_map(base_run_id, repo) if base_run_id else {}
        return comment.render(comment.diff_verdicts(base, head), repo=repo)

    def _verdict_map(self, run_id: str | None, repo: str) -> dict[str, dict[str, Any]]:
        if run_id is None:
            return {}
        rows = self.db.query(
            "SELECT v.alert_key, v.verdict_json, a.purl, a.ghsa_id FROM verdicts v "
            "JOIN alerts a ON a.alert_key = v.alert_key WHERE v.run_id=? AND a.repo=?",
            (run_id, repo),
        )
        out: dict[str, dict[str, Any]] = {}
        for row in rows:
            verdict = json.loads(row["verdict_json"])
            verdict.setdefault("purl", row["purl"])
            verdict.setdefault("ghsa_id", row["ghsa_id"])
            out[str(row["alert_key"])] = verdict
        return out

    @staticmethod
    def _write(directory: Any, repo: str, filename: str, payload: dict[str, Any]) -> str:
        target = directory / repo.replace("/", "__")
        target.mkdir(parents=True, exist_ok=True)
        path = target / filename
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return str(path)


def _tristate(value: Any) -> bool | None:
    """SQLite stores the validator outcome as 1/0/NULL; NULL means nobody checked."""
    if value is None:
        return None
    return bool(value)
