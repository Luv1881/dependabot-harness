"""CLI preflight and provider-aware credential gating.

The failure these cover is a one-line configuration problem — an unset API key —
surfacing as a retried authentication error deep inside an agent loop, after ingest has
already run. The check belongs before any work starts, and the message has to name the
environment variable to set.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.cli import build_parser, preflight_model_credentials
from harness.config import HarnessConfig, load_config
from harness.models import ProviderConfigurationError
from harness.scan import agents_available

BASE = """
github:
  org: my-org
  repos: [my-org/a]
models:
  recon: {provider: %(recon_provider)s, model: claude-haiku-4-5}
  judgment: {provider: %(judgment_provider)s, model: claude-opus-5}
  validator: {provider: %(validator_provider)s, model: claude-sonnet-5}
  dedup: {provider: anthropic, model: claude-haiku-4-5}
budgets:
  per_repo_usd: 5.0
  per_alert_usd: 0.4
  per_run_usd: 100.0
cache:
  invalidate_architecture_on_paths: ["**/go.mod"]
output:
  vex_dir: ./out/vex
  sarif_dir: ./out/sarif
"""


def write_config(tmp_path: Path, *, providers: str = "anthropic") -> Path:
    text = BASE % {
        "recon_provider": providers,
        "judgment_provider": providers,
        "validator_provider": "openai" if providers == "anthropic" else "anthropic",
    }
    path = tmp_path / "harness.yaml"
    path.write_text(text)
    return path


@pytest.fixture(autouse=True)
def _token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_TOKEN", "ghp_test")


def cfg_for(tmp_path: Path, *, providers: str = "anthropic") -> HarnessConfig:
    return load_config(write_config(tmp_path, providers=providers))


class TestPreflight:
    def test_a_missing_key_names_the_variable_to_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ProviderConfigurationError) as exc:
            preflight_model_credentials(cfg_for(tmp_path))
        assert "ANTHROPIC_API_KEY" in str(exc.value)

    def test_every_configured_provider_is_checked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A config that mixes providers needs every key, not just the first one."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        with pytest.raises(ProviderConfigurationError) as exc:
            preflight_model_credentials(cfg_for(tmp_path))
        assert "OPENAI_API_KEY" in str(exc.value)

    def test_a_complete_set_of_keys_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        preflight_model_credentials(cfg_for(tmp_path))

    def test_the_message_says_where_to_put_the_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ProviderConfigurationError) as exc:
            preflight_model_credentials(cfg_for(tmp_path))
        assert "Export the named variable" in str(exc.value)


class TestAgentsAvailableIsProviderAware:
    """`auto` used to look only for ANTHROPIC_API_KEY, so an OpenAI-configured run was
    enabled and then failed inside the first stage."""

    def test_an_openai_config_with_only_an_anthropic_key_is_not_ready(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        cfg = cfg_for(tmp_path, providers="openai")
        assert agents_available(cfg) is False

    def test_an_openai_config_with_its_own_key_is_ready(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")  # validator slot
        assert agents_available(cfg_for(tmp_path, providers="openai")) is True


class TestParserSurface:
    def test_run_has_no_hidden_agent_switch(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["run"])
        assert args.command == "run"

    def test_scan_public_rejects_an_unknown_agent_mode(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["scan-public", "--repo", "o/r", "--agents", "maybe"])
