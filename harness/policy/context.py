"""Facts a rule may consult, and the outcome vocabulary rules emit."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from ..analysis.imports import ImportIndex
from ..db import AlertRecord


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
    detail: dict[str, Any] = field(default_factory=dict)

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
            "detail": self.detail,
        }


class RepoFacts(Protocol):
    """Repo-level evidence a rule may need. Implementations decide how to source it."""

    def import_index(self, ecosystem: str) -> ImportIndex: ...

    def production_build_targets(self) -> list[str] | None: ...

    def newer_advisory_for(self, alert: AlertRecord) -> str | None: ...


@dataclass(frozen=True)
class RuleContext:
    alert: AlertRecord
    facts: RepoFacts
    thresholds: dict[str, float] = field(default_factory=dict)

    @property
    def ecosystem(self) -> str:
        return self.alert.ecosystem
