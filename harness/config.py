"""Config loading, ``${ENV}`` interpolation, and startup assertions.

Secrets come from the environment only. Nothing here is ever written to the DB;
``config_hash`` is computed over the config with secret-bearing values stripped.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .util import config_hash

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")

_SECRET_KEYS = frozenset({"app_id", "installation_id", "private_key_path", "token"})


class ConfigError(ValueError):
    """Config is malformed, or violates an invariant that must fail at startup."""


def _expand(node: Any) -> Any:
    """Recursively substitute ``${VAR}``. Unset vars resolve to None, not the literal."""
    if isinstance(node, dict):
        return {k: _expand(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_expand(v) for v in node]
    if isinstance(node, str):
        match = _ENV_PATTERN.fullmatch(node.strip())
        if match:
            return os.environ.get(match.group(1))
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), node)
    return node


def _strip_secrets(node: Any) -> Any:
    if isinstance(node, dict):
        return {
            k: ("<secret>" if k in _SECRET_KEYS else _strip_secrets(v)) for k, v in node.items()
        }
    if isinstance(node, list):
        return [_strip_secrets(v) for v in node]
    return node


@dataclass(frozen=True)
class ModelConfig:
    """One routed model slot. ``max_tokens`` is the hard 25% context ceiling (§1.4)."""

    role: str
    provider: str
    model: str
    context_window: int
    max_context_fraction: float = 0.25

    @property
    def max_context_tokens(self) -> int:
        return int(self.context_window * self.max_context_fraction)

    @property
    def identity(self) -> tuple[str, str]:
        return (self.provider, self.model)


@dataclass(frozen=True)
class GithubConfig:
    org: str
    repos: tuple[str, ...]
    app_id: str | None = None
    installation_id: str | None = None
    private_key_path: str | None = None
    token: str | None = None

    @property
    def uses_app_auth(self) -> bool:
        return bool(self.app_id and self.installation_id and self.private_key_path)


@dataclass(frozen=True)
class BudgetConfig:
    per_repo_usd: float
    per_alert_usd: float
    per_run_usd: float
    judgment_max_tool_calls: int
    on_breach: str

    def __post_init__(self) -> None:
        if self.on_breach not in {"queue_next_run", "fail", "warn"}:
            raise ConfigError(f"budgets.on_breach: unknown value {self.on_breach!r}")


@dataclass(frozen=True)
class CacheConfig:
    dir: Path
    architecture_ttl_days: int
    verdict_ttl_days: int
    invalidate_architecture_on_paths: tuple[str, ...]


@dataclass(frozen=True)
class StorageConfig:
    db_path: Path
    checkout_dir: Path


@dataclass(frozen=True)
class OutputConfig:
    vex_dir: Path
    sarif_dir: Path
    auto_dismiss: bool
    auto_dismiss_requires: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HarnessConfig:
    github: GithubConfig
    models: dict[str, ModelConfig]
    budgets: BudgetConfig
    cache: CacheConfig
    storage: StorageConfig
    output: OutputConfig
    hash: str
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def model(self, role: str) -> ModelConfig:
        try:
            return self.models[role]
        except KeyError as exc:
            raise ConfigError(f"no model configured for role {role!r}") from exc


def _require(mapping: dict[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise ConfigError(f"{where}: missing required key {key!r}")
    return mapping[key]


def load_config(path: str | Path = "config/harness.yaml") -> HarnessConfig:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    raw = _expand(yaml.safe_load(path.read_text()) or {})
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")

    gh = _require(raw, "github", str(path))
    repos = tuple(gh.get("repos") or ())
    if not repos:
        raise ConfigError("github.repos: explicit allowlist is required (no wildcard discovery)")
    for repo in repos:
        if repo.count("/") != 1:
            raise ConfigError(f"github.repos: {repo!r} must be 'owner/name'")
    github = GithubConfig(
        org=_require(gh, "org", "github"),
        repos=repos,
        app_id=gh.get("app_id"),
        installation_id=gh.get("installation_id"),
        private_key_path=gh.get("private_key_path"),
        token=os.environ.get("GH_TOKEN"),
    )
    if not github.uses_app_auth and not github.token:
        raise ConfigError(
            "github auth unavailable: set GH_APP_ID + GH_INSTALLATION_ID + "
            "GH_PRIVATE_KEY_PATH, or GH_TOKEN"
        )

    models: dict[str, ModelConfig] = {}
    for role, spec in (_require(raw, "models", str(path))).items():
        models[role] = ModelConfig(
            role=role,
            provider=_require(spec, "provider", f"models.{role}"),
            model=_require(spec, "model", f"models.{role}"),
            context_window=int(spec.get("context_window", 200_000)),
            max_context_fraction=float(spec.get("max_context_fraction", 0.25)),
        )

    budgets_raw = _require(raw, "budgets", str(path))
    budgets = BudgetConfig(
        per_repo_usd=float(_require(budgets_raw, "per_repo_usd", "budgets")),
        per_alert_usd=float(_require(budgets_raw, "per_alert_usd", "budgets")),
        per_run_usd=float(_require(budgets_raw, "per_run_usd", "budgets")),
        judgment_max_tool_calls=int(budgets_raw.get("judgment_max_tool_calls", 8)),
        on_breach=str(budgets_raw.get("on_breach", "queue_next_run")),
    )

    cache_raw = _require(raw, "cache", str(path))
    cache = CacheConfig(
        dir=Path(cache_raw.get("dir", "./out/cache")),
        architecture_ttl_days=int(cache_raw.get("architecture_ttl_days", 30)),
        verdict_ttl_days=int(cache_raw.get("verdict_ttl_days", 90)),
        invalidate_architecture_on_paths=tuple(
            cache_raw.get("invalidate_architecture_on_paths") or ()
        ),
    )
    if not cache.invalidate_architecture_on_paths:
        raise ConfigError(
            "cache.invalidate_architecture_on_paths must be non-empty: it is the only "
            "input to structure_hash, and an empty list would never invalidate recon"
        )

    storage_raw = raw.get("storage") or {}
    storage = StorageConfig(
        db_path=Path(storage_raw.get("db_path", "./out/harness.db")),
        checkout_dir=Path(storage_raw.get("checkout_dir", "./out/checkouts")),
    )

    output_raw = _require(raw, "output", str(path))
    output = OutputConfig(
        vex_dir=Path(output_raw.get("vex_dir", "./out/vex")),
        sarif_dir=Path(output_raw.get("sarif_dir", "./out/sarif")),
        auto_dismiss=bool(output_raw.get("auto_dismiss", False)),
        auto_dismiss_requires=dict(output_raw.get("auto_dismiss_requires") or {}),
    )

    cfg = HarnessConfig(
        github=github,
        models=models,
        budgets=budgets,
        cache=cache,
        storage=storage,
        output=output,
        hash=config_hash(_strip_secrets(raw)),
        raw=raw,
    )
    assert_model_divergence(cfg)
    return cfg


def assert_model_divergence(cfg: HarnessConfig) -> None:
    """§11.7b — nothing grades its own homework. Fail loudly at startup, not mid-run.

    The spec's example config diverges on provider; the requirement is that provider
    *or* model differ. We enforce the pair.
    """
    judgment = cfg.models.get("judgment")
    validator = cfg.models.get("validator")
    if judgment is None or validator is None:
        raise ConfigError("models.judgment and models.validator are both required")
    if judgment.identity == validator.identity:
        raise ConfigError(
            "models.validator must differ from models.judgment in provider or model — "
            f"both are {judgment.provider}/{judgment.model}. The stage that confirms a "
            "verdict cannot be the stage that produced it."
        )


def load_policy(path: str | Path = "config/policy.yaml") -> dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"policy file not found: {path}")
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data
