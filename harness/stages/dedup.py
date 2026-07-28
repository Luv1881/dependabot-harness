"""Stage 3 — Dedup. Deterministic index first, then a narrow agent on the shortlist.

Non-canonical members inherit the canonical verdict and never reach Judgment. That is
where the saving comes from, and also where the risk is: an over-eager cluster makes an
alert inherit a conclusion nobody reasoned about for it. The agent is therefore asked one
question with one shape of answer, and every cluster it proposes is validated against the
alerts it was actually shown.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import HarnessConfig
from ..db import AlertRecord, Database
from ..dedup import Cluster, InvertedIndex, trivial_clusters
from ..models import BudgetLedger, ModelClient, ModelError, ModelRequest
from ..models.client import ContextCeilingExceeded
from ..schemas import SchemaViolation, validate
from ..util import RetryExhausted, canonical_json

log = logging.getLogger(__name__)

STAGE = "dedup"
ROLE = "dedup"

_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "dedup.md"


@dataclass
class DedupReport:
    run_id: str
    alerts: int = 0
    clusters: int = 0
    suppressed: int = 0
    agent_calls: int = 0
    all_pairs_comparisons: int = 0
    shortlisted_comparisons: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def judgment_invocations_saved(self) -> int:
        return self.suppressed

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "alerts": self.alerts,
            "clusters": self.clusters,
            "suppressed": self.suppressed,
            "judgment_invocations_saved": self.judgment_invocations_saved,
            "agent_calls": self.agent_calls,
            "all_pairs_comparisons": self.all_pairs_comparisons,
            "shortlisted_comparisons": self.shortlisted_comparisons,
        }


class DedupStage:
    def __init__(
        self,
        cfg: HarnessConfig,
        db: Database,
        ledger: BudgetLedger,
        *,
        client: ModelClient | None = None,
        use_agent: bool = True,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.ledger = ledger
        self.client = client or ModelClient(cfg.model(ROLE), ledger)
        self.use_agent = use_agent
        self.prompt = _PROMPT_PATH.read_text()

    def run(self, run_id: str) -> DedupReport:
        report = DedupReport(run_id=run_id)
        alerts = [a for repo in self.cfg.github.repos for a in self.db.alerts_for_repo(repo)]
        pending = [a for a in alerts if self._needs_dedup(run_id, a)]
        if not pending:
            return report

        report.alerts = len(pending)
        index = InvertedIndex.build(pending)
        report.all_pairs_comparisons, report.shortlisted_comparisons = index.comparisons_avoided()

        clusters = list(trivial_clusters(index))
        clustered = {key for c in clusters for key in c.members}

        if self.use_agent:
            remaining = [a for a in pending if a.alert_key not in clustered]
            clusters.extend(self._agent_clusters(index, remaining, clustered, report))

        self._record(run_id, index, clusters, report)
        return report

    def _agent_clusters(
        self,
        index: InvertedIndex,
        remaining: list[AlertRecord],
        clustered: set[str],
        report: DedupReport,
    ) -> list[Cluster]:
        out: list[Cluster] = []
        for alert in remaining:
            if alert.alert_key in clustered:
                continue
            shortlist = [k for k in index.candidates(alert) if k not in clustered]
            if not shortlist:
                continue

            decision = self.ledger.check(repo=alert.repo)
            if not decision.allowed:
                report.errors.append(f"budget {decision.scope} cap reached; dedup deferred")
                break

            proposed = self._ask(index, alert, shortlist, report)
            for cluster in proposed:
                if any(m in clustered for m in cluster.members):
                    continue
                clustered.update(cluster.members)
                out.append(cluster)
        return out

    def _ask(
        self,
        index: InvertedIndex,
        alert: AlertRecord,
        shortlist: list[str],
        report: DedupReport,
    ) -> list[Cluster]:
        allowed = {alert.alert_key, *shortlist}
        request = ModelRequest(
            system=self.prompt,
            user=(
                "## Alert under consideration\n```json\n"
                f"{canonical_json(_describe(alert))}\n```\n\n"
                "## Candidates\n```json\n"
                f"{canonical_json([_describe(index.alerts[k]) for k in shortlist])}\n```"
            ),
            max_tokens=2_000,
            cacheable_prefix=self.prompt,
        )
        try:
            response = self.client.complete(request, repo=alert.repo, stage=STAGE)
            report.agent_calls += 1
            payload = response.json()
            validate("dedup_response", payload)
        except (ModelError, RetryExhausted, ContextCeilingExceeded, SchemaViolation) as exc:
            log.warning("dedup agent unavailable for %s: %s", alert.alert_key, exc)
            report.errors.append(f"dedup agent failed for {alert.alert_key}: {exc}")
            return []

        return _validated_clusters(payload, allowed, index)

    def _record(
        self,
        run_id: str,
        index: InvertedIndex,
        clusters: list[Cluster],
        report: DedupReport,
    ) -> None:
        report.clusters = len(clusters)
        clustered: set[str] = set()

        with self.db.transaction():
            for cluster in clusters:
                for member in cluster.members:
                    clustered.add(member)
                    is_canonical = member == cluster.canonical
                    self.db.query(
                        "INSERT INTO dedup_clusters(cluster_id, alert_key, is_canonical, "
                        "rationale) VALUES(?,?,?,?) ON CONFLICT(cluster_id, alert_key) DO "
                        "UPDATE SET is_canonical=excluded.is_canonical",
                        (cluster.cluster_id, member, int(is_canonical), cluster.rationale),
                    )
                    if is_canonical:
                        self.db.record_stage(
                            run_id=run_id,
                            alert_key=member,
                            stage=STAGE,
                            status="done",
                            payload={"cluster_id": cluster.cluster_id, "canonical": True},
                        )
                    else:
                        report.suppressed += 1
                        self.db.record_stage(
                            run_id=run_id,
                            alert_key=member,
                            stage=STAGE,
                            status="skipped",
                            payload={
                                "cluster_id": cluster.cluster_id,
                                "canonical": False,
                                "inherits_from": cluster.canonical,
                                "rationale": cluster.rationale,
                            },
                        )

            for key in index.alerts:
                if key not in clustered:
                    self.db.record_stage(
                        run_id=run_id,
                        alert_key=key,
                        stage=STAGE,
                        status="done",
                        payload={"cluster_id": None, "canonical": True},
                    )

    def _needs_dedup(self, run_id: str, alert: AlertRecord) -> bool:
        if self.db.is_stage_complete(run_id, alert.alert_key, STAGE):
            return False
        return self.db.stage_status(run_id, alert.alert_key, "policy") == "done"


def propagate_verdicts(db: Database, run_id: str) -> int:
    """Copy each canonical verdict onto its non-canonical members.

    Runs after judgment so that a suppressed alert still carries a verdict, marked with
    the alert it inherited from rather than presented as its own analysis.

    Validator agreement is deliberately NOT inherited. The validator examined the
    canonical alert, not this one, and carrying its approval across would let an
    inherited verdict satisfy the auto-dismissal gate on a review it never received.
    An inherited verdict is therefore always unconfirmed, which the gate blocks.
    """
    rows = db.query(
        "SELECT cluster_id, alert_key FROM dedup_clusters WHERE is_canonical=0",
    )
    copied = 0
    for row in rows:
        cluster_id = str(row["cluster_id"])
        member = str(row["alert_key"])
        canonical_rows = db.query(
            "SELECT alert_key FROM dedup_clusters WHERE cluster_id=? AND is_canonical=1",
            (cluster_id,),
        )
        if not canonical_rows:
            continue
        source = db.latest_verdict(str(canonical_rows[0]["alert_key"]))
        if source is None:
            continue
        verdict = dict(source["verdict"])
        verdict["alert_key"] = member
        verdict["inherited_from"] = str(canonical_rows[0]["alert_key"])
        verdict["decided_by"] = "dedup_inheritance"
        verdict["validator_agreed"] = None
        db.put_verdict(
            alert_key=member,
            run_id=run_id,
            verdict=verdict,
            validated=None,
            validator_notes=(
                f"inherited from {canonical_rows[0]['alert_key']}; "
                "the validator did not examine this alert"
            ),
            structure_hash=source["structure_hash"],
        )
        copied += 1
    return copied


def _describe(alert: AlertRecord) -> dict[str, Any]:
    return {
        "alert_key": alert.alert_key,
        "repo": alert.repo,
        "ghsa_id": alert.ghsa_id,
        "purl": alert.purl,
        "manifest_path": alert.manifest_path,
        "resolved_version": alert.resolved_ver,
        "patched_version": alert.patched_ver,
        "is_direct": alert.is_direct,
        "cvss": alert.cvss_score,
        "symbols": alert.symbols or [],
    }


def _validated_clusters(
    payload: dict[str, Any], allowed: set[str], index: InvertedIndex
) -> list[Cluster]:
    """Discard anything the agent invented.

    A cluster naming an alert it was not shown, or whose canonical is not a member, is
    dropped rather than repaired: a malformed grouping would silently suppress analysis.
    """
    out: list[Cluster] = []
    for entry in payload.get("clusters") or []:
        members = tuple(dict.fromkeys(str(m) for m in entry.get("members") or []))
        canonical = str(entry.get("canonical", ""))
        if len(members) < 2 or canonical not in members:
            continue
        if not set(members) <= allowed:
            log.warning("dedup agent proposed alerts outside the shortlist; discarded")
            continue
        if any(m not in index.alerts for m in members):
            continue
        out.append(
            Cluster(
                cluster_id=f"agent:{canonical}",
                canonical=canonical,
                members=members,
                rationale=str(entry.get("rationale") or "agent cluster"),
            )
        )
    return out
