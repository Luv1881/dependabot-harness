from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from harness.config import BudgetConfig, ConfigError, ModelConfig, load_config
from harness.db import Database
from harness.models import (
    BudgetExceeded,
    BudgetLedger,
    ModelClient,
    ModelError,
    ModelRequest,
    ModelResponse,
    ProviderConfigurationError,
    ResponseClass,
    Usage,
    build_provider,
    classify,
    price,
    required_api_key_env,
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


BASE_CONFIG = """
github:
  org: my-org
  repos: [my-org/a]
models:
  recon: {provider: anthropic, model: claude-haiku-4-5}
  judgment: {provider: anthropic, model: claude-opus-5}
  validator: {provider: anthropic, model: claude-sonnet-5}
  dedup: {provider: anthropic, model: claude-haiku-4-5}
budgets: {per_repo_usd: 5.0, per_alert_usd: 0.4, per_run_usd: 100.0}
cache:
  invalidate_architecture_on_paths: ["**/go.mod"]
output: {vex_dir: ./out/vex, sarif_dir: ./out/sarif}
"""


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


class TestPermanentProviderErrorsAreNotRetried:
    """A missing key, a rejected key, or an absent SDK fails identically on the third
    attempt. Retrying it turns a one-line configuration error into a `RetryExhausted`
    that names nothing, and the operator learns only that something went wrong."""

    def test_a_401_from_the_provider_is_not_retried(self, db: Database) -> None:
        class Rejected(Exception):
            status_code = 401

        class Denied:
            def __init__(self) -> None:
                self.calls = 0

            def complete(self, request: ModelRequest, model: str) -> ModelResponse:
                self.calls += 1
                raise Rejected("invalid x-api-key")

        provider = Denied()
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        client = ModelClient(model_cfg(), ledger, provider=provider, max_attempts=3)
        with pytest.raises(ProviderConfigurationError, match="invalid x-api-key"):
            client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")
        assert provider.calls == 1

    def test_a_missing_sdk_is_a_configuration_error_not_an_exhausted_retry(
        self, db: Database
    ) -> None:
        class NoSdk:
            def complete(self, request: ModelRequest, model: str) -> ModelResponse:
                raise ModuleNotFoundError("No module named 'anthropic'")

        ledger = BudgetLedger(budget_cfg(), db, "run1")
        client = ModelClient(
            model_cfg(provider="anthropic"), ledger, provider=NoSdk(), max_attempts=3
        )
        with pytest.raises(ProviderConfigurationError, match="pip install anthropic"):
            client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")

    def test_a_configuration_error_is_marked_non_retryable(self) -> None:
        error = ProviderConfigurationError("set ANTHROPIC_API_KEY")
        assert error.is_retryable is False
        assert error.classification is ResponseClass.CONFIG

    def test_a_connection_reset_is_still_transient(self, db: Database) -> None:
        class Flaky:
            def __init__(self) -> None:
                self.calls = 0

            def complete(self, request: ModelRequest, model: str) -> ModelResponse:
                self.calls += 1
                if self.calls == 1:
                    raise ConnectionError("connection reset by peer")
                return ok()

        provider = Flaky()
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        client = ModelClient(model_cfg(), ledger, provider=provider)
        assert client.complete(
            ModelRequest(system="s", user="u"), repo="org/a", stage="recon"
        ).is_usable
        assert provider.calls == 2


class TestProviderCredentialsAreCheckedBeforeUse:
    def test_an_unset_key_names_the_variable_to_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ProviderConfigurationError, match="ANTHROPIC_API_KEY"):
            build_provider("anthropic")
    def test_a_set_key_constructs_the_provider_without_importing_the_sdk(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Constructing the provider must not require the vendor package: the SDK import
        is deferred until the first call so an unused provider costs nothing."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-value")
        provider = build_provider("anthropic")
        assert provider.name == "anthropic"
        assert provider._api_key == "sk-test-value"

    def test_each_provider_maps_to_its_own_environment_variable(self) -> None:
        assert required_api_key_env("anthropic") == "ANTHROPIC_API_KEY"
        assert required_api_key_env("openai") == "OPENAI_API_KEY"
        assert required_api_key_env("unknown-vendor") is None

    def test_an_unknown_provider_is_still_a_plain_value_error(self) -> None:
        with pytest.raises(ValueError, match="unknown model provider"):
            build_provider("nonexistent")


class TestDeepSeekProvider:
    """DeepSeek speaks the OpenAI wire format, so it is the same implementation with a
    different endpoint — not a copy that drifts from it."""

    def test_it_is_registered_under_its_own_name(self) -> None:
        from harness.models.client import PROVIDERS, DeepSeekProvider

        assert PROVIDERS["deepseek"] is DeepSeekProvider
        assert DeepSeekProvider.name == "deepseek"

    def test_its_key_is_its_own_environment_variable(self) -> None:
        assert required_api_key_env("deepseek") == "DEEPSEEK_API_KEY"

    def test_it_does_not_fall_back_to_an_openai_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A key belonging to one vendor must never be sent to another vendor's endpoint.

        Pointing an OpenAI key at DeepSeek, or the reverse, is a misroute that works well
        enough to be noticed only on the invoice.
        """
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-key")
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        with pytest.raises(ProviderConfigurationError, match="DEEPSEEK_API_KEY"):
            build_provider("deepseek")

    def test_a_deepseek_key_constructs_it_without_the_sdk(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-key")
        provider = build_provider("deepseek")
        assert provider._api_key == "sk-deepseek-key"  # type: ignore[attr-defined]
        assert provider.base_url == "https://api.deepseek.com/v1"  # type: ignore[attr-defined]

    def test_its_endpoint_matches_what_the_catalogue_queries(self) -> None:
        """The provider and the `harness models` diagnostic must not drift apart."""
        from harness.models.catalogue import ENDPOINTS
        from harness.models.client import DeepSeekProvider

        assert DeepSeekProvider.base_url == ENDPOINTS["deepseek"].base_url

    def test_openai_keeps_the_sdk_default_endpoint(self) -> None:
        from harness.models.client import OpenAIProvider

        assert OpenAIProvider.base_url is None


class TestOutputTokenCeiling:
    """Stages ask for what their job needs, sized against one vendor's limits. A model
    with a lower output cap rejects the call outright, so the configured value wins."""
    class Recorder:
        name = "recorder"

        def __init__(self) -> None:
            self.max_tokens: int | None = None

        def complete(self, request: ModelRequest, model: str) -> ModelResponse:
            self.max_tokens = request.max_tokens
            return ok()

    def _client(self, db: Database, **cfg_kw: Any) -> ModelClient:
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        return ModelClient(
            model_cfg(**cfg_kw), ledger, provider=self.Recorder(), max_attempts=1
        )

    def test_a_request_above_the_cap_is_clamped(self, db: Database) -> None:
        client = self._client(db, max_output_tokens=1024)
        client.complete(
            ModelRequest(system="s", user="u", max_tokens=8_000),
            repo="org/a",
            stage="judgment",
        )
        assert client.provider.max_tokens == 1024  # type: ignore[attr-defined]

    def test_a_request_below_the_cap_is_untouched(self, db: Database) -> None:
        client = self._client(db, max_output_tokens=16_384)
        client.complete(
            ModelRequest(system="s", user="u", max_tokens=8_000),
            repo="org/a",
            stage="judgment",
        )
        assert client.provider.max_tokens == 8_000  # type: ignore[attr-defined]

    def test_no_configured_cap_leaves_the_stage_in_charge(self, db: Database) -> None:
        client = self._client(db)
        client.complete(
            ModelRequest(system="s", user="u", max_tokens=8_000),
            repo="org/a",
            stage="judgment",
        )
        assert client.provider.max_tokens == 8_000  # type: ignore[attr-defined]

    def test_the_callers_request_object_is_not_mutated(self, db: Database) -> None:
        """The tool loop appends to the request it owns across rounds; clamping must not
        reach back into it."""
        request = ModelRequest(system="s", user="u", max_tokens=8_000)
        client = self._client(db, max_output_tokens=1024)
        client.complete(request, repo="org/a", stage="judgment")
        assert request.max_tokens == 8_000


class TestPricingIsNotOptional:
    """An unpriced model must be reported as unpriced, never as free.

    `price` returns 0.0 for a model outside its table, the ledger sums zeros, and the
    budget check therefore observes a spend of nothing forever — so every cap silently
    stops working. Discovered by running 36 paid DeepSeek calls and reading `spend_usd:
    $0.000000` back.
    """

    def test_a_model_with_no_rates_is_identifiable(self) -> None:
        from harness.models import is_priced

        assert is_priced("claude-opus-5") is True
        assert is_priced("deepseek-flash") is False

    def test_declared_rates_make_a_model_priced(self) -> None:
        from harness.models import is_priced

        assert is_priced("deepseek-flash", (0.28, 0.42)) is True

    def test_declared_rates_produce_a_real_cost(self) -> None:
        from harness.models import price

        usage = Usage(tokens_in=1_000_000, tokens_out=100_000)
        assert price("deepseek-flash", usage, (1.0, 2.0)) == pytest.approx(1.2)

    def test_an_unpriced_model_costs_zero_but_is_not_priced(self) -> None:
        from harness.models import is_priced, price

        usage = Usage(tokens_in=1_000_000, tokens_out=100_000)
        assert price("deepseek-flash", usage) == 0.0
        assert is_priced("deepseek-flash") is False

    def test_a_half_declared_price_is_refused_by_config(self, tmp_path: Path) -> None:
        """Understating spend is worse than not stating it, because it quietly relaxes
        the cap it feeds."""
        text = BASE_CONFIG.replace(
            "  recon: {provider: anthropic, model: claude-haiku-4-5}",
            "  recon:\n    provider: anthropic\n    model: claude-haiku-4-5\n"
            "    pricing: {input_per_mtok: 1.0}",
            1,
        )
        path = tmp_path / "h.yaml"
        path.write_text(text)
        with pytest.raises(ConfigError, match="output_per_mtok"):
            load_config(path, require_github_auth=False)

    def test_declared_rates_are_read_from_config(self, tmp_path: Path) -> None:
        text = BASE_CONFIG.replace(
            "  recon: {provider: anthropic, model: claude-haiku-4-5}",
            "  recon:\n    provider: anthropic\n    model: claude-haiku-4-5\n"
            "    pricing: {input_per_mtok: 0.28, output_per_mtok: 0.42}",
            1,
        )
        path = tmp_path / "h.yaml"
        path.write_text(text)
        cfg = load_config(path, require_github_auth=False)
        assert cfg.model("recon").pricing == (0.28, 0.42)
        assert cfg.model("judgment").pricing is None

    def test_declared_rates_reach_the_ledger(self, db: Database) -> None:
        """End to end: a priced role records a non-zero cost."""
        from harness.models import BudgetLedger

        cfg = model_cfg(model="deepseek-flash", pricing=(1.0, 2.0))
        ledger = BudgetLedger(budget_cfg(), db, "run1")
        client = ModelClient(cfg, ledger, provider=FakeProvider(ok()), max_attempts=1)
        client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")
        assert db.spend("run1") > 0
        assert db.unpriced_calls("run1") == 0
        assert client.unpriced is False

    def test_an_unpriced_call_is_counted_and_reported(self, db: Database) -> None:
        from harness.models import BudgetLedger

        ledger = BudgetLedger(budget_cfg(), db, "run1")
        client = ModelClient(
            model_cfg(model="deepseek-flash"),
            ledger,
            provider=FakeProvider(ok()),
            max_attempts=1,
        )
        client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")
        assert client.unpriced is True
        assert db.unpriced_calls("run1") == 1
        report = ledger.report()
        assert report["spend_is_complete"] is False
        assert report["unpriced_calls"] == 1

    def test_a_fully_priced_run_reports_a_complete_spend(self, db: Database) -> None:
        from harness.models import BudgetLedger

        ledger = BudgetLedger(budget_cfg(), db, "run1")
        client = ModelClient(
            model_cfg(model="claude-opus-5"),
            ledger,
            provider=FakeProvider(ok()),
            max_attempts=1,
        )
        client.complete(ModelRequest(system="s", user="u"), repo="org/a", stage="recon")
        assert ledger.report()["spend_is_complete"] is True


class TestOpenAiStopReasonVocabulary:
    """`classify` reads a neutral stop reason. OpenAI-shaped vendors use different words
    for the same states, and an untranslated `length` matches nothing — so a truncated
    completion is classified as a complete, usable answer and the retry that exists for
    exactly that case never fires.

    Found by running against DeepSeek: a real call returned `finish_reason='stop'`.
    """

    def test_length_becomes_max_tokens(self) -> None:
        from harness.models.client import _neutral_stop_reason

        assert _neutral_stop_reason("length") == "max_tokens"
        assert classify("partial", stop_reason=_neutral_stop_reason("length")).kind is (
            ResponseClass.TRUNCATED
        )

    def test_content_filter_becomes_refusal(self) -> None:
        from harness.models.client import _neutral_stop_reason

        assert _neutral_stop_reason("content_filter") == "refusal"
        assert classify("x", stop_reason=_neutral_stop_reason("content_filter")).kind is (
            ResponseClass.REFUSAL
        )

    def test_ordinary_reasons_pass_through(self) -> None:
        from harness.models.client import _neutral_stop_reason

        assert _neutral_stop_reason("stop") == "stop"
        assert _neutral_stop_reason("tool_calls") == "tool_calls"
        assert _neutral_stop_reason(None) is None

    def test_anthropic_vocabulary_is_untouched(self) -> None:
        from harness.models.client import _neutral_stop_reason

        assert _neutral_stop_reason("max_tokens") == "max_tokens"
        assert _neutral_stop_reason("refusal") == "refusal"


class TestToolCallTranslation:
    """The compatible vendors do not return Anthropic-shaped content blocks, and their
    tool calls arrive as JSON in a string. Without translation the judgment agent is
    handed no tool surface at all and runs blind.
    """

    class Function:
        def __init__(self, name: str, arguments: str) -> None:
            self.name = name
            self.arguments = arguments

    class Call:
        def __init__(self, id_: str, name: str, arguments: str) -> None:
            self.id = id_
            self.function = TestToolCallTranslation.Function(name, arguments)

    class Message:
        def __init__(self, content: str | None, calls: list[object]) -> None:
            self.content = content
            self.tool_calls = calls

    def test_tool_declarations_become_openai_functions(self) -> None:
        from harness.models.client import _openai_tools

        translated = _openai_tools(
            [
                {
                    "name": "grep",
                    "description": "search",
                    "input_schema": {"type": "object", "properties": {"pattern": {}}},
                }
            ]
        )
        assert translated[0]["type"] == "function"
        assert translated[0]["function"]["name"] == "grep"
        assert translated[0]["function"]["parameters"]["type"] == "object"

    def test_a_declaration_without_a_schema_still_translates(self) -> None:
        from harness.models.client import _openai_tools

        translated = _openai_tools([{"name": "read_file"}])
        assert translated[0]["function"]["parameters"] == {"type": "object", "properties": {}}

    def test_arguments_come_back_as_a_mapping(self) -> None:
        from harness.models.client import _tool_arguments

        assert _tool_arguments('{"path": "a.go", "start": 3}') == {
            "path": "a.go",
            "start": 3,
        }

    def test_unparsable_arguments_degrade_to_empty_rather_than_raising(self) -> None:
        """The tool then reports a missing argument and the model can correct itself;
        raising would discard the whole turn over one malformed field."""
        from harness.models.client import _tool_arguments

        assert _tool_arguments("{not json") == {}
        assert _tool_arguments(None) == {}
        assert _tool_arguments("[1,2]") == {}

    def test_a_response_becomes_neutral_blocks(self) -> None:
        from harness.models.client import _neutral_blocks

        message = self.Message("thinking", [self.Call("call_1", "grep", '{"pattern": "x"}')])
        blocks = _neutral_blocks(message)
        assert blocks[0] == {"type": "text", "text": "thinking"}
        assert blocks[1] == {
            "type": "tool_use",
            "id": "call_1",
            "name": "grep",
            "input": {"pattern": "x"},
        }

    def test_the_agent_loop_can_read_the_calls(self) -> None:
        from harness.models.client import _tool_calls

        calls = _tool_calls(self.Message(None, [self.Call("c1", "grep", '{"pattern":"x"}')]))
        assert calls[0]["name"] == "grep"
        assert calls[0]["id"] == "c1"

    def test_history_round_trips_through_openai_shape(self) -> None:
        """The loop replays the assistant turn and the tool results; both have to be
        expressed the way the vendor expects them."""
        from harness.models.client import _openai_messages

        request = ModelRequest(system="s", user="find it")
        request.history.append(
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "looking"},
                    {"type": "tool_use", "id": "c1", "name": "grep", "input": {"pattern": "x"}},
                ],
            }
        )
        request.history.append(
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "c1", "content": "a.go:1: x"}],
            }
        )
        messages = _openai_messages(request)
        assert messages[0] == {"role": "user", "content": "find it"}
        assistant = messages[1]
        assert assistant["role"] == "assistant"
        assert assistant["content"] == "looking"
        assert assistant["tool_calls"][0]["id"] == "c1"
        assert assistant["tool_calls"][0]["function"]["name"] == "grep"
        assert json.loads(assistant["tool_calls"][0]["function"]["arguments"]) == {
            "pattern": "x"
        }
        assert messages[2] == {
            "role": "tool",
            "tool_call_id": "c1",
            "content": "a.go:1: x",
        }

    def test_one_assistant_message_carries_text_and_calls_together(self) -> None:
        """Two consecutive assistant turns are rejected by the API."""
        from harness.models.client import _openai_assistant_turn

        turns = _openai_assistant_turn(
            [
                {"type": "text", "text": "looking"},
                {"type": "tool_use", "id": "c1", "name": "grep", "input": {}},
            ]
        )
        assert len(turns) == 1
        assert turns[0]["content"] == "looking"
        assert len(turns[0]["tool_calls"]) == 1

    def test_an_empty_turn_emits_nothing(self) -> None:
        from harness.models.client import _openai_assistant_turn

        assert _openai_assistant_turn([]) == []


class TestContextEstimateIsPessimistic:
    def test_estimate_does_not_undershoot_a_conservative_ratio(self) -> None:
        request = ModelRequest(system="x" * 3000, user="")
        assert request.estimated_tokens() >= 1000
