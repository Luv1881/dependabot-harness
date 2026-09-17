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

    def test_models_is_a_command(self) -> None:
        parser = build_parser()
        assert parser.parse_args(["models"]).command == "models"

    def test_scan_local_is_a_command(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan-local", "--path", "/tmp/x"])
        assert args.command == "scan-local"
        assert args.path == "/tmp/x"

    def test_env_file_is_a_global_option(self) -> None:
        parser = build_parser()
        assert parser.parse_args(["--env-file", ".env", "run"]).env_file == ".env"
        assert parser.parse_args(["run"]).env_file is None


class TestEnvFileIsAppliedBeforeConfigLoad:
    """The shell incantation for exporting a dotenv file is not portable — `set -a; .
    ./.env; set +a` is bash, and under fish it is three errors. Accepting the file
    directly removes the shell from the equation."""

    def _config(self, tmp_path: Path) -> Path:
        path = tmp_path / "harness.yaml"
        path.write_text(DEEPSEEK_CONFIG)
        return path

    def test_a_key_can_arrive_only_via_the_env_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from harness import cli

        monkeypatch.setenv("GH_TOKEN", "ghp_test")
        for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        env = tmp_path / ".env"
        env.write_text("ANTHROPIC_API_KEY=sk-a\nOPENAI_API_KEY=sk-b\nDEEPSEEK_API_KEY=sk-c\n")
        monkeypatch.setattr(cli, "list_models", lambda provider, key: [f"{provider}-m"])

        assert (
            cli.main(
                ["--config", str(self._config(tmp_path)), "--env-file", str(env), "models"]
            )
            == 0
        )
        assert "deepseek-m" in capsys.readouterr().out

    def test_the_file_is_not_loaded_without_the_flag(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Implicit secret loading is how a stray file in a working directory changes what
        a run does. The flag is the whole opt-in."""
        from harness import cli

        monkeypatch.setenv("GH_TOKEN", "ghp_test")
        for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        (tmp_path / ".env").write_text("DEEPSEEK_API_KEY=sk-c\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(cli, "list_models", lambda provider, key: [f"{provider}-m"])

        assert cli.main(["--config", str(self._config(tmp_path)), "models"]) == 1
        assert "DEEPSEEK_API_KEY is not set" in capsys.readouterr().out

    def test_a_broken_env_file_exits_two_without_a_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from harness import cli

        monkeypatch.setenv("GH_TOKEN", "ghp_test")
        bad = tmp_path / "bad.env"
        bad.write_text("NOT A PAIR\n")
        argv = ["--config", str(self._config(tmp_path)), "--env-file", str(bad), "run"]
        assert cli.main(argv) == 2

    def test_a_missing_env_file_exits_two(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from harness import cli

        monkeypatch.setenv("GH_TOKEN", "ghp_test")
        assert cli.main(["--env-file", str(tmp_path / "absent"), "report"]) == 2

    def test_a_credential_error_points_at_a_dotenv_that_has_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The harness never loads `.env` on its own. But when the missing variable is
        sitting in a file right there, saying so turns a hunt into a one-line fix."""
        from harness.cli import _with_env_hint

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("DEEPSEEK_API_KEY=sk-x\n")
        hinted = _with_env_hint("model credentials are missing: needs DEEPSEEK_API_KEY.")
        assert "--env-file .env" in hinted
        assert "DEEPSEEK_API_KEY" in hinted

    def test_no_hint_when_the_file_does_not_define_the_variable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from harness.cli import _with_env_hint

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SOMETHING_ELSE=1\n")
        message = "needs DEEPSEEK_API_KEY."
        assert _with_env_hint(message) == message

    def test_no_hint_when_there_is_no_dotenv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from harness.cli import _with_env_hint

        monkeypatch.chdir(tmp_path)
        message = "needs DEEPSEEK_API_KEY."
        assert _with_env_hint(message) == message


DEEPSEEK_CONFIG = BASE % {
    "recon_provider": "deepseek",
    "judgment_provider": "deepseek",
    "validator_provider": "openai",
}


class TestModelsCommand:
    """`harness models` resolves a tier name to the identifier the API actually accepts.

    It talks to the provider's listing endpoint, so it must work before a config has
    been proven correct and without demanding credentials it has no use for.
    """

    def _config(self, tmp_path: Path) -> Path:
        path = tmp_path / "harness.yaml"
        path.write_text(DEEPSEEK_CONFIG)
        return path

    def test_it_does_not_require_a_github_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from harness import cli
        from harness.models import CatalogueError

        monkeypatch.delenv("GH_TOKEN", raising=False)
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

        def fake(provider: str, api_key: str) -> list[str]:
            if provider == "deepseek":
                return ["deepseek-chat", "deepseek-reasoner"]
            raise CatalogueError(f"{provider}: HTTP 500")

        monkeypatch.setattr(cli, "list_models", fake)
        args = cli.build_parser().parse_args(["--config", str(self._config(tmp_path)), "models"])
        assert cli.cmd_models(args) == 1
        assert "deepseek-chat" in capsys.readouterr().out

    def test_a_missing_key_is_reported_per_provider(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from harness import cli

        monkeypatch.setenv("GH_TOKEN", "ghp_test")
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setattr(cli, "list_models", lambda provider, key: [f"{provider}-model"])

        args = cli.build_parser().parse_args(["--config", str(self._config(tmp_path)), "models"])
        assert cli.cmd_models(args) == 1
        assert "DEEPSEEK_API_KEY is not set" in capsys.readouterr().out

    def test_a_full_success_exits_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from harness import cli

        monkeypatch.setenv("GH_TOKEN", "ghp_test")
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")  # the dedup slot in BASE
        monkeypatch.setattr(cli, "list_models", lambda provider, key: [f"{provider}-flash"])

        args = cli.build_parser().parse_args(["--config", str(self._config(tmp_path)), "models"])
        assert cli.cmd_models(args) == 0
        assert "deepseek-flash" in capsys.readouterr().out

    def test_the_shipped_deepseek_config_loads(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The committed single-model config must be loadable, not aspirational."""
        from harness import cli

        monkeypatch.setenv("GH_TOKEN", "ghp_test")
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
        monkeypatch.setattr(cli, "list_models", lambda provider, key: ["deepseek-chat"])

        args = cli.build_parser().parse_args(["--config", "config/deepseek.yaml", "models"])
        assert cli.cmd_models(args) == 0
