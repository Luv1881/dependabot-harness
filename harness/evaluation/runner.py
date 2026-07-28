"""Runs a pipeline over the golden set and scores it.

The deterministic-only pipeline (policy rules + evidence) is the M4 baseline. Later
milestones plug in judgment and validation behind the same ``Predictor`` protocol, so the
same numbers stay comparable across milestones.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..analysis.imports import ImportIndex
from ..db import AlertRecord
from ..ecosystems.base import ReachabilityLevel
from ..policy import PolicyEngine, RuleContext
from ..policy.context import OutcomeKind
from ..util import utcnow
from .dataset import GoldenCase, GoldenSet
from .metrics import EvalReport, Outcome


@dataclass(frozen=True)
class Prediction:
    verdict: str
    confidence: float = 0.0
    cost_usd: float = 0.0
    validator_agreed: bool | None = None
    decided_by: str = ""
    rule_id: str | None = None


class Predictor(Protocol):
    name: str

    def predict(self, case: GoldenCase) -> Prediction: ...


@dataclass
class GoldenFacts:
    """Repo facts as recorded on the golden case, not sourced from a live checkout."""

    case: GoldenCase

    def import_index(self, ecosystem: str) -> ImportIndex:
        if self.case.imports_scanned is None:
            return ImportIndex.unavailable("golden case records no import scan")
        return ImportIndex(scanned=True, modules=set(self.case.imports_scanned), files_scanned=1)

    def production_build_targets(self) -> list[str] | None:
        return self.case.production_build_targets

    def newer_advisory_for(self, alert: AlertRecord) -> str | None:
        return self.case.superseded_by


class DeterministicPredictor:
    """Policy rules plus recorded evidence. No model is invoked, so cost is zero."""

    name = "deterministic"

    def __init__(self, engine: PolicyEngine) -> None:
        self.engine = engine

    def predict(self, case: GoldenCase) -> Prediction:
        alert = to_alert(case)
        outcome = self.engine.evaluate(RuleContext(alert=alert, facts=GoldenFacts(case)))
        if outcome is not None and outcome.kind is not OutcomeKind.DEDUP:
            return Prediction(
                verdict=outcome.verdict or "could_not_determine",
                confidence=1.0,
                decided_by="policy",
                rule_id=outcome.rule_id,
            )
        return Prediction(
            verdict=self._from_evidence(case),
            confidence=case.reachability_confidence or 0.0,
            decided_by="evidence" if _is_measurement(case) else "unresolved",
        )

    @staticmethod
    def _from_evidence(case: GoldenCase) -> str:
        """Without a judgment agent, only unambiguous evidence decides.

        A dismissal requires a positive measurement: a named method that is not
        `failed`, an explicit level, and non-zero confidence. A level of 0 carrying no
        confidence is an unset field, not a finding that the package is absent, and
        reading it as a clearance is the false-negative this whole set exists to catch.
        """
        if not _is_measurement(case):
            return "could_not_determine"
        level = case.reachability_level
        assert level is not None
        if level >= ReachabilityLevel.PATH_FROM_ENTRY:
            return "affected"
        if level <= ReachabilityLevel.PRESENT:
            return "not_affected"
        return "could_not_determine"


def _is_measurement(case: GoldenCase) -> bool:
    """Whether the case carries evidence a tool actually produced."""
    if case.reachability_level is None:
        return False
    if not case.reachability_method or case.reachability_method == "failed":
        return False
    return bool(case.reachability_confidence)


def to_alert(case: GoldenCase) -> AlertRecord:
    return AlertRecord(
        alert_key=case.case_id,
        repo=case.repo,
        ghsa_id=case.ghsa_id,
        cve_id=None,
        purl=case.purl,
        ecosystem=case.ecosystem,
        manifest_path=case.manifest_path,
        gh_alert_num=1,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        state="open",
        resolved_ver=case.resolved_version,
        patched_ver=case.patched_version,
        dep_scope=case.dep_scope,
        is_direct=case.is_direct,
        cvss_score=case.cvss_score,
        epss_score=case.epss_score,
        in_kev=case.in_kev,
        severity=case.severity,
        symbols=list(case.symbols) or None,
    )


def evaluate(golden: GoldenSet, predictor: Predictor, *, split_name: str = "tune") -> EvalReport:
    report = EvalReport(split=split_name)
    for case in golden:
        prediction = predictor.predict(case)
        report.outcomes.append(
            Outcome(
                case_id=case.case_id,
                label=case.label,
                verdict=prediction.verdict,
                confidence=prediction.confidence,
                cost_usd=prediction.cost_usd,
                validator_agreed=prediction.validator_agreed,
                decided_by=prediction.decided_by,
                rule_id=prediction.rule_id,
            )
        )
    return report


def summarize(golden: GoldenSet, predictor: Predictor) -> dict[str, Any]:
    return {
        "predictor": predictor.name,
        "dataset": {
            "total": len(golden),
            "labels": golden.label_counts(),
            "ecosystems": golden.ecosystem_counts(),
            "tune": len(golden.tune),
            "holdout": len(golden.holdout),
        },
        "tune": evaluate(golden.tune, predictor, split_name="tune").to_dict(),
    }
