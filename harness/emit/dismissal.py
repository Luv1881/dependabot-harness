"""Auto-dismissal gating.

Dismissal is the only outward-facing write that closes an alert, so the gate is
conjunctive and every clause must be explicitly satisfied. An unknown is never treated as
a pass: a verdict nobody confirmed is not a confirmed verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

DISMISSED_REASON = "tolerable_risk"

REQUIRED_GATE_KEYS = ("verdict", "confidence_min", "validator_agreed")


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reasons: tuple[str, ...] = ()

    @property
    def blocked_by(self) -> str:
        return "; ".join(self.reasons)


@dataclass
class DismissalGate:
    """Evaluates `output.auto_dismiss_requires` against one verdict."""

    enabled: bool
    requirements: dict[str, Any] = field(default_factory=dict)

    def evaluate(self, verdict: dict[str, Any], validated: bool | None) -> GateDecision:
        """Fail closed.

        An absent requirement is not a satisfied requirement. A config that enables
        auto-dismissal without stating what it requires would otherwise dismiss
        everything, which is the worst possible reading of an omission.
        """
        if not self.enabled:
            return GateDecision(False, ("auto_dismiss is disabled",))

        missing = [k for k in REQUIRED_GATE_KEYS if k not in self.requirements]
        if missing:
            return GateDecision(
                False,
                (
                    f"auto_dismiss_requires is missing {', '.join(missing)}; refusing to "
                    "dismiss against an unstated bar",
                ),
            )

        blockers: list[str] = []

        if "verdict" not in verdict:
            blockers.append("verdict document has no verdict field")

        required_verdict = self.requirements.get("verdict")
        if verdict.get("verdict") != required_verdict:
            blockers.append(
                f"verdict is {verdict.get('verdict')!r}, gate requires {required_verdict!r}"
            )

        minimum = float(self.requirements["confidence_min"])
        confidence = float(verdict.get("confidence") or 0.0)
        if confidence < minimum:
            blockers.append(f"confidence {confidence} is below the required {minimum}")

        if self.requirements.get("validator_agreed") and validated is not True:
            state = "unconfirmed" if validated is None else "disputed"
            blockers.append(f"validator {state}; the gate requires explicit agreement")

        if verdict.get("needs_human"):
            blockers.append("verdict is flagged for human review")

        if verdict.get("verdict") == "not_affected" and not verdict.get("vex_justification"):
            blockers.append("not_affected without a justification code")

        return GateDecision(not blockers, tuple(blockers))


def dismissal_comment(verdict: dict[str, Any]) -> str:
    """The comment left on the alert. Carries the justification code and the evidence."""
    lines = [
        f"Dismissed by triage-harness: {verdict.get('verdict')}.",
        f"VEX justification: {verdict.get('vex_justification')}",
        f"Confidence: {verdict.get('confidence')}",
    ]
    rationale = verdict.get("severity_rationale")
    if rationale:
        lines.append(f"Rationale: {rationale}")

    citations = verdict.get("evidence_cited") or []
    if citations:
        lines.append("Evidence:")
        lines.extend(f"  - {c.get('file')}:{c.get('line')} — {c.get('why')}" for c in citations)
    else:
        lines.append("Evidence: none cited.")

    return "\n".join(lines)
