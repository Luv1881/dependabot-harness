from __future__ import annotations

import json
from typing import Any

import pytest

from harness.config import BudgetConfig, ModelConfig
from harness.db import Database
from harness.models import (
    BudgetExceeded,
    BudgetLedger,
    ModelClient,
    ModelError,
    ModelRequest,
    ModelResponse,
    ResponseClass,
    Usage,
    classify,
    price,
)
from harness.models.client import ContextCeilingExceeded
from harness.util import RetryExhausted


class FakeProvider:
    name = "fake"

    def __init__(self, *responses: ModelResponse) -> None:
        self.queue = list(responses)
        self.last = responses[-1]
        self.calls = 0

    def complete(self, request: ModelRequest, model: str) -> ModelResponse:
        self.calls += 1
        if self.queue:
            self.last = self.queue.pop(0)
        return self.last


def ok(text: str = '{"ok": true}', **kw: Any) -> ModelResponse:
    return ModelResponse(text=text, usage=Usage(tokens_in=100, tokens_out=50), **kw)


def model_cfg(**kw: Any) -> ModelConfig:
    defaults: dict[str, Any] = dict(
        role="recon",
        provider="fake",
        model="claude-haiku-4-5",
        context_window=200_000,
        max_context_fraction=0.25,
    )
    defaults.update(kw)
    return ModelConfig(**defaults)


def budget_cfg(**kw: Any) -> BudgetConfig:
    defaults: dict[str, Any] = dict(
        per_repo_usd=5.0,
        per_alert_usd=0.4,
        per_run_usd=100.0,
        judgment_max_tool_calls=8,
        on_breach="queue_next_run",
    )
    defaults.update(kw)
    return BudgetConfig(**defaults)


class TestResponseClassification:
    """The failure mode: a transient error arriving as text inside a 200 OK."""

    def test_clean_text_is_ok(self) -> None:
        assert classify("here is the answer").kind is ResponseClass.OK

    def test_empty_body_is_not_a_success(self) -> None:
        assert classify("").kind is ResponseClass.EMPTY
        assert classify("   \n ").kind is ResponseClass.EMPTY
        assert classify(None).kind is ResponseClass.EMPTY

    @pytest.mark.parametrize(
        "body",
        [
            '{"error": {"type": "overloaded_error", "message": "Overloaded"}}',
            '{"error": {"type": "rate_limit_error"}}',
            "Internal Server Error",
            "upstream connect error or disconnect/reset before headers",
            "<!DOCTYPE html><html><body>502 Bad Gateway</body></html>",
            "Service Unavailable",
            "The service is temporarily unavailable, please retry",
        ],
    )
    def test_error_text_inside_a_success_is_transient(self, body: str) -> None:
        result = classify(body)
        assert result.kind is ResponseClass.TRANSIENT
        assert result.is_retryable
        assert not result.is_usable

    def test_a_normal_stop_reason_does_not_launder_an_error_body(self) -> None:
        """A degraded provider reports end_turn alongside an error page."""
        result = classify('{"error": {"type": "api_error"}}', stop_reason="end_turn")
        assert result.kind is ResponseClass.TRANSIENT

    def test_refusal_is_not_retryable(self) -> None:
        result = classify("I cannot help with that", stop_reason="refusal")
        assert result.kind is ResponseClass.REFUSAL
        assert not result.is_retryable

    def test_truncation_is_flagged(self) -> None:
        assert classify("partial answer", stop_reason="max_tokens").kind is ResponseClass.TRUNCATED

    def test_prose_mentioning_an_error_is_still_usable(self) -> None:
        assert classify("The handler returns a wrapped error value.").kind is ResponseClass.OK


class TestPricing:
    def test_known_model_priced(self) -> None:
        cost = price("claude-opus-5", Usage(tokens_in=1_000_000, tokens_out=1_000_000))
        assert cost == pytest.approx(30.0)

    def test_cache_reads_are_cheaper(self) -> None:
        full = price("claude-opus-5", Usage(tokens_in=1_000_000))
        cached = price("claude-opus-5", Usage(cache_read_tokens=1_000_000))
        assert cached == pytest.approx(full * 0.1)

    def test_unknown_model_is_zero_not_a_crash(self) -> None:
        assert price("some-future-model", Usage(tokens_in=1000)) == 0.0


class TestBudgetLedger:
    def test_records_and_accumulates(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        ledger.record(
            repo="org/a", stage="recon", model="claude-opus-5", usage=Usage(tokens_in=1_000_000)
        )
        assert db.spend("run1", repo="org/a") == pytest.approx(5.0)

    def test_recon_is_charged_to_the_repo_not_an_alert(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        ledger.record(
            repo="org/a", stage="recon", model="claude-opus-5", usage=Usage(tokens_in=100_000)
        )
        assert db.spend("run1", repo="org/a") > 0
        assert db.spend("run1", alert_key="k1") == 0.0

    def test_repo_cap_blocks_before_run_cap(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(per_repo_usd=1.0), db, "run1")
        ledger.record(
            repo="org/a", stage="recon", model="claude-opus-5", usage=Usage(tokens_in=1_000_000)
        )
        decision = ledger.check(repo="org/a")
        assert decision.allowed is False
        assert decision.scope == "repo"
        assert decision.defer is True

    def test_a_busy_repo_does_not_block_a_quiet_one(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(per_repo_usd=1.0), db, "run1")
        ledger.record(
            repo="org/a", stage="recon", model="claude-opus-5", usage=Usage(tokens_in=1_000_000)
        )
        assert ledger.check(repo="org/b").allowed is True

    def test_alert_cap_enforced(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(per_alert_usd=0.01), db, "run1")
        ledger.record(
            repo="org/a",
            stage="judgment",
            model="claude-opus-5",
            usage=Usage(tokens_in=100_000),
            alert_key="k1",
        )
        assert ledger.check(repo="org/a", alert_key="k1").allowed is False
        assert ledger.check(repo="org/a", alert_key="k2").allowed is True

    def test_fail_policy_raises(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(per_repo_usd=0.01, on_breach="fail"), db, "run1")
        ledger.record(
            repo="org/a", stage="recon", model="claude-opus-5", usage=Usage(tokens_in=1_000_000)
        )
        with pytest.raises(BudgetExceeded):
            ledger.check(repo="org/a")

    def test_spend_survives_a_new_ledger_instance(self, db: Database) -> None:
        BudgetLedger(budget_cfg(), db, "run1").record(
            repo="org/a", stage="recon", model="claude-opus-5", usage=Usage(tokens_in=1_000_000)
        )
        assert db.spend("run1") == pytest.approx(5.0)


class TestModelClient:
    def test_successful_call_is_ledgered(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        client = ModelClient(model_cfg(), ledger, provider=FakeProvider(ok()))
        response = client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")
        assert response.is_usable
        assert db.spend("run1", repo="org/a") > 0

    def test_transient_body_is_retried_then_succeeds(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        provider = FakeProvider(ok(text='{"error": {"type": "overloaded_error"}}'), ok())
        client = ModelClient(model_cfg(), ledger, provider=provider)
        response = client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")
        assert response.is_usable
        assert provider.calls == 2

    def test_a_failed_attempt_is_still_ledgered(self, db: Database) -> None:
        """Tokens spent on a failed attempt were still spent."""
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        provider = FakeProvider(ok(text='{"error": {"type": "overloaded_error"}}'), ok())
        ModelClient(model_cfg(), ledger, provider=provider).complete(
            ModelRequest(system="s", user="u"), repo="org/a", stage="recon"
        )
        rows = db.query("SELECT COUNT(*) AS n FROM budget_ledger WHERE run_id='run1'")
        assert rows[0]["n"] == 2

    def test_persistent_failure_raises(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        provider = FakeProvider(ok(text="Internal Server Error"))
        client = ModelClient(model_cfg(), ledger, provider=provider, max_attempts=2)
        with pytest.raises(RetryExhausted):
            client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")

    def test_empty_completion_never_reads_as_success(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        client = ModelClient(
            model_cfg(), ledger, provider=FakeProvider(ok(text="")), max_attempts=1
        )
        with pytest.raises(RetryExhausted):
            client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")


class TestContextCeiling:
    def test_oversized_context_is_refused_before_the_call(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        provider = FakeProvider(ok())
        client = ModelClient(model_cfg(context_window=1000), ledger, provider=provider)
        request = ModelRequest(system="x" * 100_000, user="u")
        with pytest.raises(ContextCeilingExceeded, match="ceiling"):
            client.complete(request, repo="org/a", stage="recon")
        assert provider.calls == 0

    def test_ceiling_is_twenty_five_percent(self) -> None:
        assert model_cfg(context_window=1_000_000).max_context_tokens == 250_000

    def test_context_within_the_ceiling_is_allowed(self, db: Database) -> None:
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        client = ModelClient(model_cfg(context_window=200_000), ledger, provider=FakeProvider(ok()))
        request = ModelRequest(system="x" * 1000, user="u")
        assert client.complete(request, repo="org/a", stage="recon").is_usable


class TestResponseParsing:
    def test_plain_json(self) -> None:
        assert ok(text='{"a": 1}').json() == {"a": 1}

    def test_fenced_json(self) -> None:
        assert ok(text='```json\n{"a": 1}\n```').json() == {"a": 1}

    def test_json_with_surrounding_prose(self) -> None:
        assert ok(text='Here is the result:\n{"a": 1}\nHope that helps.').json() == {"a": 1}

    def test_no_json_raises(self) -> None:
        with pytest.raises(ModelError):
            ok(text="no object here").json()

    def test_malformed_json_raises(self) -> None:
        with pytest.raises(ModelError):
            ok(text='{"a": }').json()


class TestProviderIsolation:
    def test_no_provider_sdk_leaks_into_the_public_surface(self) -> None:
        """Provider types must not escape client.py."""
        import harness.models as models

        for name in models.__all__:
            module = getattr(models, name).__module__
            assert module.startswith("harness."), f"{name} leaks {module}"

    def test_response_carries_only_plain_types(self) -> None:
        response = ok()
        assert isinstance(response.text, str)
        assert isinstance(response.usage, Usage)
        assert isinstance(json.dumps(response.tool_calls), str)


class TestClassifierDoesNotMisreadProse:
    """An agent describing a service is reporting a finding, not failing."""

    def test_long_prose_mentioning_errors_is_usable(self) -> None:
        body = (
            "The API enforces a rate limit at the edge and returns Internal Server Error "
            "on malformed request bodies. Upstream connect errors are retried. "
        ) * 3
        assert classify(body).kind is ResponseClass.OK

    def test_json_document_mentioning_errors_is_usable(self) -> None:
        body = json.dumps(
            {
                "summary": "Service applies a rate limit and returns Service Unavailable "
                "when the pool is exhausted.",
                "confidence": 0.8,
            }
        )
        assert classify(body).kind is ResponseClass.OK

    def test_bare_error_string_is_still_transient(self) -> None:
        assert classify("Internal Server Error").kind is ResponseClass.TRANSIENT

    def test_error_json_is_still_transient_however_long(self) -> None:
        body = json.dumps({"error": {"type": "overloaded_error", "message": "x" * 5000}})
        assert classify(body).kind is ResponseClass.TRANSIENT

    def test_markup_body_is_transient_at_any_length(self) -> None:
        body = "<!DOCTYPE html><html><body>" + "padding " * 500 + "502</body></html>"
        assert classify(body).kind is ResponseClass.TRANSIENT


class TestProviderExceptionHandling:
    def test_provider_exception_is_retried_not_propagated_raw(self, db: Database) -> None:
        class Flaky:
            def __init__(self) -> None:
                self.calls = 0

            def complete(self, request: ModelRequest, model: str) -> ModelResponse:
                self.calls += 1
                if self.calls == 1:
                    raise ConnectionError("connection reset by peer")
                return ok()

        ledger = BudgetLedger(budget_cfg(), db, "run1")
        provider = Flaky()
        client = ModelClient(model_cfg(), ledger, provider=provider)
        response = client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")
        assert response.is_usable
        assert provider.calls == 2

    def test_persistent_provider_exception_surfaces_as_retry_exhaustion(self, db: Database) -> None:
        class Broken:
            def complete(self, request: ModelRequest, model: str) -> ModelResponse:
                raise ConnectionError("network unreachable")

        ledger = BudgetLedger(budget_cfg(), db, "run1")
        client = ModelClient(model_cfg(), ledger, provider=Broken(), max_attempts=2)
        with pytest.raises(RetryExhausted):
            client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")


class TestContextEstimateIsPessimistic:
    def test_estimate_does_not_undershoot_a_conservative_ratio(self) -> None:
        request = ModelRequest(system="x" * 3000, user="")
        assert request.estimated_tokens() >= 1000
