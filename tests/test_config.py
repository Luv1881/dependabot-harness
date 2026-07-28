from __future__ import annotations

from pathlib import Path

import pytest

from harness.config import ConfigError, load_config

BASE = """
github:
  org: my-org
  repos: [my-org/a]
models:
  recon: {provider: anthropic, model: claude-haiku-4-5}
  judgment: {provider: anthropic, model: claude-opus-5, context_window: 1000000}
  validator: {provider: anthropic, model: claude-sonnet-5}
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


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "harness.yaml"
    path.write_text(text)
    return path


@pytest.fixture(autouse=True)
def _token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_TOKEN", "ghp_test")


def test_loads_and_normalizes(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, BASE))
    assert cfg.github.repos == ("my-org/a",)
    assert cfg.model("judgment").model == "claude-opus-5"
    assert cfg.budgets.on_breach == "queue_next_run"


def test_context_ceiling_is_25_percent(tmp_path: Path) -> None:
    """§1.4 — no agent invocation may exceed 25% of the model context window."""
    cfg = load_config(write(tmp_path, BASE))
    judgment = cfg.model("judgment")
    assert judgment.max_context_tokens == 250_000
    assert judgment.max_context_fraction == 0.25


def test_validator_matching_judgment_fails_at_startup(tmp_path: Path) -> None:
    """§11 — nothing grades its own homework. This must fail loudly, not at runtime."""
    bad = BASE.replace(
        "validator: {provider: anthropic, model: claude-sonnet-5}",
        "validator: {provider: anthropic, model: claude-opus-5}",
    )
    with pytest.raises(ConfigError, match="must differ"):
        load_config(write(tmp_path, bad))


def test_provider_divergence_is_also_accepted(tmp_path: Path) -> None:
    diverged = BASE.replace(
        "validator: {provider: anthropic, model: claude-sonnet-5}",
        "validator: {provider: openai, model: claude-opus-5}",
    )
    assert load_config(write(tmp_path, diverged)).model("validator").provider == "openai"


def test_empty_invalidation_list_rejected(tmp_path: Path) -> None:
    """An empty list would make structure_hash constant and never invalidate recon."""
    bad = BASE.replace(
        'invalidate_architecture_on_paths: ["**/go.mod"]', "architecture_ttl_days: 30"
    )
    with pytest.raises(ConfigError, match="invalidate_architecture_on_paths"):
        load_config(write(tmp_path, bad))


def test_missing_auth_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="github auth"):
        load_config(write(tmp_path, BASE))


def test_malformed_repo_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="owner/name"):
        load_config(write(tmp_path, BASE.replace("[my-org/a]", "[justaname]")))


def test_wildcard_discovery_not_supported(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="allowlist"):
        load_config(write(tmp_path, BASE.replace("repos: [my-org/a]", "repos: []")))


def test_config_hash_excludes_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rotating a token must not invalidate every run's config_hash."""
    with_app = BASE.replace("org: my-org", "org: my-org\n  app_id: ${GH_APP_ID}")
    monkeypatch.setenv("GH_APP_ID", "111")
    first = load_config(write(tmp_path, with_app)).hash
    monkeypatch.setenv("GH_APP_ID", "222")
    assert load_config(write(tmp_path, with_app)).hash == first


def test_config_hash_changes_with_real_config(tmp_path: Path) -> None:
    first = load_config(write(tmp_path, BASE)).hash
    second = load_config(write(tmp_path, BASE.replace("per_alert_usd: 0.4", "per_alert_usd: 0.9")))
    assert second.hash != first


def test_env_interpolation_of_unset_var_is_none_not_literal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GH_INSTALLATION_ID", raising=False)
    text = BASE.replace("org: my-org", "org: my-org\n  installation_id: ${GH_INSTALLATION_ID}")
    cfg = load_config(write(tmp_path, text))
    assert cfg.github.installation_id is None
