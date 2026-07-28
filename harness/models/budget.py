"""Token and cost accounting, and the per-repo caps.

Caps are enforced per repository because cost varies wildly across repos: a per-run cap
alone lets one pathological repo consume the whole budget.

Every model call is ledgered. A call that cannot be ledgered does not happen.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..config import BudgetConfig
from ..db import Database


class BreachAction(StrEnum):
    QUEUE_NEXT_RUN = "queue_next_run"
    FAIL = "fail"
    WARN = "warn"


class BudgetExceeded(RuntimeError):
    """A cap was hit and the configured policy is to fail."""

    def __init__(self, scope: str, spent: float, cap: float) -> None:
        super().__init__(f"{scope} budget exceeded: ${spent:.4f} of ${cap:.2f}")
        self.scope = scope
        self.spent = spent
        self.cap = cap


PRICING_USD_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-4-8": (5.0, 25.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-fable-5": (10.0, 50.0),
}

_CACHE_READ_MULTIPLIER = 0.1
_CACHE_WRITE_MULTIPLIER = 1.25


@dataclass(frozen=True)
class Usage:
    tokens_in: int = 0
    tokens_out: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total(self) -> int:
        return self.tokens_in + self.tokens_out + self.cache_read_tokens + self.cache_write_tokens


def price(model: str, usage: Usage) -> float:
    """Cost in USD. An unpriced model is charged zero and must be surfaced, not guessed."""
    rates = PRICING_USD_PER_MTOK.get(model)
    if rates is None:
        return 0.0
    input_rate, output_rate = rates
    return (
        usage.tokens_in * input_rate
        + usage.cache_read_tokens * input_rate * _CACHE_READ_MULTIPLIER
        + usage.cache_write_tokens * input_rate * _CACHE_WRITE_MULTIPLIER
        + usage.tokens_out * output_rate
    ) / 1_000_000


def is_priced(model: str) -> bool:
    return model in PRICING_USD_PER_MTOK


@dataclass
class BudgetDecision:
    allowed: bool
    scope: str = ""
    spent: float = 0.0
    cap: float = 0.0
    action: BreachAction = BreachAction.WARN

    @property
    def defer(self) -> bool:
        return not self.allowed and self.action is BreachAction.QUEUE_NEXT_RUN


class BudgetLedger:
    """Reads and writes spend through the database so caps survive a crash."""

    def __init__(self, cfg: BudgetConfig, db: Database, run_id: str) -> None:
        self.cfg = cfg
        self.db = db
        self.run_id = run_id
        self.action = BreachAction(cfg.on_breach)

    def check(self, *, repo: str, alert_key: str | None = None) -> BudgetDecision:
        """Whether another call is permitted at run, repo and alert scope."""
        run_spent = self.db.spend(self.run_id)
        if run_spent >= self.cfg.per_run_usd:
            return self._breach("run", run_spent, self.cfg.per_run_usd)

        repo_spent = self.db.spend(self.run_id, repo=repo)
        if repo_spent >= self.cfg.per_repo_usd:
            return self._breach("repo", repo_spent, self.cfg.per_repo_usd)

        if alert_key is not None:
            alert_spent = self.db.spend(self.run_id, alert_key=alert_key)
            if alert_spent >= self.cfg.per_alert_usd:
                return self._breach("alert", alert_spent, self.cfg.per_alert_usd)

        return BudgetDecision(allowed=True, action=self.action)

    def _breach(self, scope: str, spent: float, cap: float) -> BudgetDecision:
        if self.action is BreachAction.FAIL:
            raise BudgetExceeded(scope, spent, cap)
        return BudgetDecision(allowed=False, scope=scope, spent=spent, cap=cap, action=self.action)

    def record(
        self,
        *,
        repo: str,
        stage: str,
        model: str,
        usage: Usage,
        alert_key: str | None = None,
    ) -> float:
        """Ledger one model call. Recon uses ``alert_key=None`` because it is repo-level."""
        cost = price(model, usage)
        self.db.record_cost(
            run_id=self.run_id,
            repo=repo,
            stage=stage,
            cost_usd=cost,
            alert_key=alert_key,
        )
        return cost

    def report(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "spend_usd": round(self.db.spend(self.run_id), 6),
            "caps": {
                "per_run_usd": self.cfg.per_run_usd,
                "per_repo_usd": self.cfg.per_repo_usd,
                "per_alert_usd": self.cfg.per_alert_usd,
            },
            "on_breach": self.action.value,
        }
