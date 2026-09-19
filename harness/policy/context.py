"""Facts a rule may consult, and the outcome vocabulary rules emit."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, NamedTuple, Protocol

from ..analysis.imports import ImportIndex
from ..db import AlertRecord


class SupersedingFix(NamedTuple):
    """A newer advisory for the same package whose fix subsumes this one's.

    Carries the patched version, not just the identifier: the useful remedy for a
    superseded alert is the version that fixes *both*, and reporting only this alert's own
    (lower) patch would send the operator to a version that still trips its neighbour.
    """

    ghsa_id: str
    patched_version: str | None


class OutcomeKind(StrEnum):
    VERDICT = "verdict"
    ESCALATE = "escalate"
    SKIP_ANALYSIS = "skip_analysis"
    DEDUP = "dedup"


@dataclass(frozen=True)
class RuleOutcome:
    rule_id: str
    kind: OutcomeKind
    reason: str
    verdict: str | None = None
    vex_status: str | None = None
    vex_justification: str | None = None
    needs_human: bool = False
    recommended_action: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def is_clearance(self) -> bool:
        """Whether this outcome closes the alert for good.

        `affected` is a decision but not a clearance: the dependency still needs
        upgrading. Counting the two together is what lets a report claim a backlog was
        cleared while every alert in it is still actionable.
        """
        return self.verdict is not None and self.verdict != "affected"

    @property
    def terminates_analysis(self) -> bool:
        return self.kind in {
            OutcomeKind.VERDICT,
            OutcomeKind.ESCALATE,
            OutcomeKind.SKIP_ANALYSIS,
            OutcomeKind.DEDUP,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "kind": self.kind.value,
            "reason": self.reason,
            "verdict": self.verdict,
            "vex_status": self.vex_status,
            "vex_justification": self.vex_justification,
            "needs_human": self.needs_human,
            "recommended_action": self.recommended_action,
            "detail": self.detail,
        }


class RepoFacts(Protocol):
    """Repo-level evidence a rule may need. Implementations decide how to source it."""

    def import_index(self, ecosystem: str) -> ImportIndex: ...

    def production_build_targets(self) -> list[str] | None: ...

    def superseding_fix_for(self, alert: AlertRecord) -> SupersedingFix | None: ...


@dataclass(frozen=True)
class RuleContext:
    alert: AlertRecord
    facts: RepoFacts
    thresholds: dict[str, float] = field(default_factory=dict)

    @property
    def ecosystem(self) -> str:
        return self.alert.ecosystem
