"""Rule engine: ordered evaluation, first match wins, per-rule clearance accounting."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .context import OutcomeKind, RuleContext, RuleOutcome
from .rules import RULE_TYPES, Rule


class PolicyError(ValueError):
    """policy.yaml declares a rule the engine cannot construct."""


CONFIDENCE_WHEN_ECOSYSTEM_UNKNOWN = 0.5
"""Used when no adapter exists for the ecosystem. A policy verdict is a claim about the
code, and with no adapter there is no basis for confidence in that claim."""


def policy_confidence(ecosystem: str) -> float:
    """A deterministic rule's confidence, held to the ecosystem's ceiling.

    The rule is certain of its own fact — the package appears in no import statement, the
    version is at or above the patch — but the conclusion is only as reliable as the
    ecosystem's tooling. npm's ceiling is 0.55 because bundler aliasing and
    `require(variable)` defeat static import scanning, and that caveat applies in full to
    `not_imported`.

    Emitting 1.0 instead bypassed the ceiling entirely: the check lives in the validation
    stage, and a policy-cleared alert never reaches it. On a real npm repository that
    produced 135 `not_affected` verdicts at 1.0 against a declared ceiling of 0.55 —
    comfortably over an `auto_dismiss_requires.confidence_min` of 0.85.
    """
    from ..ecosystems import get_adapter

    adapter = get_adapter(ecosystem)
    ceiling = adapter.confidence_ceiling() if adapter else CONFIDENCE_WHEN_ECOSYSTEM_UNKNOWN
    return min(1.0, ceiling)


@dataclass
class ClearanceStats:
    """What the deterministic rules did, in terms that do not flatter them.

    A terminated alert is not the same as a cleared one. `trivial_patch` and
    `kev_direct_critical` both terminate analysis and both leave the dependency needing an
    upgrade; counting those as clearances is how a report claims a backlog was cleared
    while every alert in it is still actionable.
    """

    total: int = 0
    by_rule: Counter[str] = field(default_factory=Counter)
    affected_by_rule: Counter[str] = field(default_factory=Counter)
    """Terminations whose verdict was `affected`: decided, not discharged."""

    @property
    def terminated(self) -> int:
        return sum(self.by_rule.values())

    @property
    def decided_affected(self) -> int:
        return sum(self.affected_by_rule.values())

    @property
    def cleared(self) -> int:
        """Terminations that closed the alert. `affected` is excluded deliberately."""
        return self.terminated - self.decided_affected

    @property
    def reaching_analysis(self) -> int:
        return self.total - self.terminated

    def percentages(self) -> dict[str, float]:
        if not self.total:
            return {}
        return {rule: round(n / self.total * 100, 2) for rule, n in self.by_rule.items()}

    def to_dict(self) -> dict[str, Any]:
        def pct(n: int) -> float:
            return round(n / self.total * 100, 2) if self.total else 0.0

        return {
            "total": self.total,
            "terminated": self.terminated,
            "cleared": self.cleared,
            "cleared_pct": pct(self.cleared),
            "decided_affected": self.decided_affected,
            "decided_affected_pct": pct(self.decided_affected),
            "reaching_analysis": self.reaching_analysis,
            "by_rule": dict(self.by_rule),
            "affected_by_rule": dict(self.affected_by_rule),
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
            if outcome.verdict == "affected":
                self.stats.affected_by_rule[outcome.rule_id] += 1
            return outcome
        return None

    def _validate(self, outcome: RuleOutcome) -> None:
        if outcome.kind is not OutcomeKind.DEDUP and not outcome.verdict:
            raise PolicyError(
                f"rule {outcome.rule_id}: a terminating outcome of kind "
                f"{outcome.kind.value!r} must carry a verdict; an outcome with none "
                "would bury the alert without deciding it"
            )
        if outcome.kind is OutcomeKind.DEDUP:
            # A dedup outcome decides nothing by itself; it is only legitimate if the alert
            # inherits a decision from its cluster's canonical member. A rule using this
            # kind without putting the alert in a cluster buries it — no verdict, no VEX
            # statement, and counted as cleared. That is what `superseded` did to 132 of
            # 293 alerts on a real repository, so it is now refused outright.
            raise PolicyError(
                f"rule {outcome.rule_id}: a dedup outcome decides nothing on its own, and "
                "this alert would inherit only if a cluster held it. Emit a verdict (or "
                "`skip_analysis`) instead, or create the cluster it can inherit from"
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
