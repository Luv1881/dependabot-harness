"""Rule engine: ordered evaluation, first match wins, per-rule clearance accounting."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .context import OutcomeKind, RuleContext, RuleOutcome
from .rules import RULE_TYPES, Rule


class PolicyError(ValueError):
    """policy.yaml declares a rule the engine cannot construct."""


@dataclass
class ClearanceStats:
    """How much of the backlog each rule removed before any model was touched."""

    total: int = 0
    by_rule: Counter[str] = field(default_factory=Counter)

    @property
    def cleared(self) -> int:
        return sum(self.by_rule.values())

    @property
    def reaching_analysis(self) -> int:
        return self.total - self.cleared

    def percentages(self) -> dict[str, float]:
        if not self.total:
            return {}
        return {rule: round(n / self.total * 100, 2) for rule, n in self.by_rule.items()}

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "cleared": self.cleared,
            "reaching_analysis": self.reaching_analysis,
            "cleared_pct": round(self.cleared / self.total * 100, 2) if self.total else 0.0,
            "by_rule": dict(self.by_rule),
            "by_rule_pct": self.percentages(),
        }


class PolicyEngine:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self.rules: list[Rule] = self._build(policy.get("rules") or [])
        self.thresholds = dict(policy.get("severity_thresholds") or {})
        self.valid_justifications = frozenset(policy.get("valid_vex_justifications") or ())
        self.stats = ClearanceStats()

    @staticmethod
    def _build(specs: list[dict[str, Any]]) -> list[Rule]:
        built: list[Rule] = []
        for spec in specs:
            rule_id = str(spec.get("id", ""))
            rule_type = RULE_TYPES.get(rule_id)
            if rule_type is None:
                raise PolicyError(f"no implementation registered for rule {rule_id!r}")
            built.append(rule_type(spec))
        return built

    def evaluate(self, ctx: RuleContext) -> RuleOutcome | None:
        self.stats.total += 1
        for rule in self.rules:
            outcome = rule.evaluate(ctx)
            if outcome is None:
                continue
            self._validate(outcome)
            self.stats.by_rule[outcome.rule_id] += 1
            return outcome
        return None

    def _validate(self, outcome: RuleOutcome) -> None:
        if outcome.kind is not OutcomeKind.DEDUP and not outcome.verdict:
            raise PolicyError(
                f"rule {outcome.rule_id}: a terminating outcome of kind "
                f"{outcome.kind.value!r} must carry a verdict; an outcome with none "
                "would bury the alert without deciding it"
            )
        if outcome.vex_status == "not_affected" and not outcome.vex_justification:
            raise PolicyError(
                f"rule {outcome.rule_id}: vex_status 'not_affected' requires a justification"
            )
        if (
            outcome.vex_justification
            and self.valid_justifications
            and outcome.vex_justification not in self.valid_justifications
        ):
            raise PolicyError(
                f"rule {outcome.rule_id}: {outcome.vex_justification!r} is not a CISA code"
            )

    def reset_stats(self) -> None:
        self.stats = ClearanceStats()
