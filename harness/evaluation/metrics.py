"""Evaluation metrics.

False-negative rate is the metric that matters most: wrongly dismissing a live
vulnerability is worse than having no tool at all. Every other number is secondary and a
change that improves cost while raising FN rate is a regression.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .dataset import Label

DISMISSING_VERDICTS = frozenset({"not_affected", "fixed"})
ESCALATING_VERDICTS = frozenset({"affected"})
UNDECIDED_VERDICTS = frozenset({"could_not_determine"})

ABSTENTION_TOLERANCE = 0.0


@dataclass
class Outcome:
    case_id: str
    label: Label
    verdict: str
    confidence: float = 0.0
    cost_usd: float = 0.0
    validator_agreed: bool | None = None
    decided_by: str = ""
    rule_id: str | None = None

    @property
    def is_false_negative(self) -> bool:
        """Truly reachable, but the harness dismissed it. The failure that destroys trust."""
        return self.label is Label.REACHABLE and self.verdict in DISMISSING_VERDICTS

    @property
    def is_false_positive(self) -> bool:
        return self.label is Label.NOT_REACHABLE and self.verdict in ESCALATING_VERDICTS

    @property
    def is_true_positive(self) -> bool:
        return self.label is Label.REACHABLE and self.verdict in ESCALATING_VERDICTS

    @property
    def is_true_negative(self) -> bool:
        return self.label is Label.NOT_REACHABLE and self.verdict in DISMISSING_VERDICTS

    @property
    def is_undecided(self) -> bool:
        return self.verdict in UNDECIDED_VERDICTS


@dataclass
class EvalReport:
    outcomes: list[Outcome] = field(default_factory=list)
    split: str = "tune"

    @property
    def decidable(self) -> list[Outcome]:
        """Cases whose ground truth is known. `unsure` labels cannot score correctness."""
        return [o for o in self.outcomes if o.label is not Label.UNSURE]

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def false_negatives(self) -> list[Outcome]:
        return [o for o in self.decidable if o.is_false_negative]

    @property
    def false_positives(self) -> list[Outcome]:
        return [o for o in self.decidable if o.is_false_positive]

    @property
    def true_positives(self) -> int:
        return sum(1 for o in self.decidable if o.is_true_positive)

    @property
    def true_negatives(self) -> int:
        return sum(1 for o in self.decidable if o.is_true_negative)

    @property
    def reachable_count(self) -> int:
        return sum(1 for o in self.decidable if o.label is Label.REACHABLE)

    @property
    def not_reachable_count(self) -> int:
        return sum(1 for o in self.decidable if o.label is Label.NOT_REACHABLE)

    @property
    def false_negative_rate(self) -> float:
        """Share of genuinely reachable vulnerabilities the harness dismissed."""
        return _ratio(len(self.false_negatives), self.reachable_count)

    @property
    def false_positive_rate(self) -> float:
        return _ratio(len(self.false_positives), self.not_reachable_count)

    @property
    def could_not_determine_rate(self) -> float:
        """Denominated over decidable cases only.

        Scoring abstentions against the whole set lets a large `unsure` population
        dilute the rate, hiding a pipeline that abstains on everything it was actually
        asked to decide.
        """
        return _ratio(sum(1 for o in self.decidable if o.is_undecided), len(self.decidable))

    @property
    def abstention_on_reachable_rate(self) -> float:
        """Share of genuinely reachable cases the pipeline declined to decide.

        A pipeline can drive false negatives to zero by answering
        `could_not_determine` everywhere. That is not a false negative and should not be
        scored as one, but it is useless, so it is measured explicitly and gated in
        :func:`compare`.
        """
        abstained = sum(1 for o in self.decidable if o.label is Label.REACHABLE and o.is_undecided)
        return _ratio(abstained, self.reachable_count)

    @property
    def mean_cost_per_alert(self) -> float:
        return _ratio(sum(o.cost_usd for o in self.outcomes), self.total)

    @property
    def validator_disagreement_rate(self) -> float:
        judged = [o for o in self.outcomes if o.validator_agreed is not None]
        return _ratio(sum(1 for o in judged if not o.validator_agreed), len(judged))

    @property
    def precision(self) -> float:
        flagged = self.true_positives + len(self.false_positives)
        return _ratio(self.true_positives, flagged)

    @property
    def recall(self) -> float:
        return _ratio(self.true_positives, self.reachable_count)

    def by_decider(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for outcome in self.outcomes:
            key = outcome.decided_by or "unresolved"
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def dataset_fingerprint(self) -> str:
        """Identity of the scored case set.

        Two reports over different case sets are not comparable, so the gate refuses to
        compare them rather than reporting a delta that means nothing.
        """
        joined = "|".join(sorted(o.case_id for o in self.outcomes))
        return hashlib.sha256(joined.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "split": self.split,
            "total_cases": self.total,
            "decidable_cases": len(self.decidable),
            "dataset_fingerprint": self.dataset_fingerprint,
            "abstention_on_reachable_rate": round(self.abstention_on_reachable_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "false_negatives": len(self.false_negatives),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_positives": len(self.false_positives),
            "could_not_determine_rate": round(self.could_not_determine_rate, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "mean_cost_per_alert_usd": round(self.mean_cost_per_alert, 6),
            "validator_disagreement_rate": round(self.validator_disagreement_rate, 4),
            "confusion": {
                "true_positive": self.true_positives,
                "false_positive": len(self.false_positives),
                "true_negative": self.true_negatives,
                "false_negative": len(self.false_negatives),
            },
            "decided_by": self.by_decider(),
            "false_negative_cases": [o.case_id for o in self.false_negatives],
        }


def compare(baseline: EvalReport, candidate: EvalReport) -> dict[str, Any]:
    """Gate a change.

    Rejects on three grounds, in order: the two reports do not describe the same case
    set; the false-negative rate rose; or the pipeline bought its false-negative rate by
    abstaining on more genuinely reachable cases. Cost never buys any of them.
    """
    fn_delta = candidate.false_negative_rate - baseline.false_negative_rate
    abstention_delta = (
        candidate.abstention_on_reachable_rate - baseline.abstention_on_reachable_rate
    )
    cost_delta = candidate.mean_cost_per_alert - baseline.mean_cost_per_alert
    comparable = candidate.dataset_fingerprint == baseline.dataset_fingerprint

    if not comparable:
        reason = "different case sets; the reports are not comparable"
    elif fn_delta > 0:
        reason = "false-negative rate rose; rejected regardless of cost improvement"
    elif abstention_delta > ABSTENTION_TOLERANCE:
        reason = (
            "abstention on reachable cases rose; the false-negative rate was bought "
            "by declining to answer rather than by deciding correctly"
        )
    else:
        reason = "false-negative rate held or improved without added abstention"

    return {
        "comparable": comparable,
        "false_negative_rate_delta": round(fn_delta, 4),
        "abstention_on_reachable_delta": round(abstention_delta, 4),
        "cost_delta_usd": round(cost_delta, 6),
        "accepted": comparable and fn_delta <= 0 and abstention_delta <= ABSTENTION_TOLERANCE,
        "reason": reason,
    }


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0
