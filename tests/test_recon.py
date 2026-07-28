from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.config import HarnessConfig, load_config
from harness.db import Database
from harness.models import BudgetLedger, ModelClient, ModelRequest, ModelResponse, Usage
from harness.sources.checkout import Checkout, CheckoutError
from harness.stages.recon import ReconStage, build_inventory

CONFIG = """
github:
  org: my-org
  repos: [my-org/service-a]
models:
  recon: {provider: anthropic, model: claude-haiku-4-5, context_window: 200000}
  judgment: {provider: anthropic, model: claude-opus-5}
  validator: {provider: anthropic, model: claude-sonnet-5}
  dedup: {provider: anthropic, model: claude-haiku-4-5}
budgets: {per_repo_usd: 5.0, per_alert_usd: 0.4, per_run_usd: 100.0}
cache:
  architecture_ttl_days: 30
  invalidate_architecture_on_paths: ["**/go.mod"]
output: {vex_dir: ./out/vex, sarif_dir: ./out/sarif}
"""

ARCHITECTURE = {
    "repo": "my-org/service-a",
    "summary": "Public HTTP API behind the edge load balancer.",
    "entry_points": [
        {
            "kind": "http_handler",
            "path": "cmd/api/routes.go",
            "symbol": "RegisterRoutes",
            "exposure": "internet",
            "authenticated": False,
            "notes": "unauthenticated /health and /v1/upload",
        }
    ],
    "trust_boundaries": [{"name": "edge -> api", "untrusted_input": True, "controls": ["WAF"]}],
    "build_targets": [
        {"name": "api", "entry": "cmd/api", "ships_to_prod": True},
        {"name": "devtool", "entry": "cmd/devtool", "ships_to_prod": False},
    ],
    "input_sources": ["http_body"],
    "deployment": {"in_production": True, "internet_facing": True, "replicas": "many"},
    "notable_frameworks": ["chi"],
    "confidence": 0.8,
    "gaps": ["could not determine whether cmd/worker is deployed"],
}


class FakeProvider:
    def __init__(self, text: str) -> None:
        self.text = text
        self.calls = 0
        self.last_request: ModelRequest | None = None

    def complete(self, request: ModelRequest, model: str) -> ModelResponse:
        self.calls += 1
        self.last_request = request
        return ModelResponse(text=self.text, usage=Usage(tokens_in=5000, tokens_out=800))


class FakeCheckouts:
    def __init__(self, root: Path | None, *, fail: bool = False) -> None:
        self.root = root
        self.fail = fail

    def ensure(self, repo: str, commit_sha: str) -> Checkout:
        if self.fail or self.root is None:
            raise CheckoutError("clone unavailable")
        return Checkout(repo=repo, commit_sha=commit_sha, path=self.root)


@pytest.fixture()
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessConfig:
    monkeypatch.setenv("GH_TOKEN", "ghp_test")
    path = tmp_path / "harness.yaml"
    path.write_text(CONFIG)
    loaded = load_config(path)
    object.__setattr__(loaded.storage, "db_path", tmp_path / "harness.db")
    object.__setattr__(loaded.storage, "checkout_dir", tmp_path / "checkouts")
    object.__setattr__(loaded.cache, "dir", tmp_path / "cache")
    return loaded


@pytest.fixture()
def source(tmp_path: Path) -> Path:
    root = tmp_path / "src"
    (root / "cmd" / "api").mkdir(parents=True)
    (root / "internal").mkdir(parents=True)
    (root / "go.mod").write_text("module example.com/app\n")
    (root / "Dockerfile").write_text("FROM golang:1.22\nCOPY . .\n")
    (root / "cmd" / "api" / "routes.go").write_text("package main\nfunc RegisterRoutes() {}\n")
    (root / "internal" / "util.go").write_text("package internal\n")
    return root


def build(
    cfg: HarnessConfig, db: Database, provider: FakeProvider, checkouts: FakeCheckouts
) -> ReconStage:
    ledger = BudgetLedger(cfg.budgets, db, "run1")
    client = ModelClient(cfg.model("recon"), ledger, provider=provider)
    return ReconStage(cfg, db, ledger, client=client, checkouts=checkouts)


class TestInventoryAssembly:
    def test_inventory_is_bounded_and_deterministic(self, source: Path) -> None:
        first = build_inventory(source, "my-org/service-a")
        second = build_inventory(source, "my-org/service-a")
        assert first == second

    def test_inventory_includes_manifests_and_entry_points(self, source: Path) -> None:
        inventory = build_inventory(source, "my-org/service-a")
        assert "go.mod" in inventory
        assert "Dockerfile" in inventory
        assert "cmd/api/routes.go" in inventory

    def test_inventory_excludes_unremarkable_files_from_excerpts(self, source: Path) -> None:
        inventory = build_inventory(source, "my-org/service-a")
        assert "package internal" not in inventory

    def test_agent_never_receives_the_whole_repository(self, source: Path) -> None:
        for index in range(50):
            (source / f"filler{index}.go").write_text("x" * 10_000)
        inventory = build_inventory(source, "my-org/service-a")
        assert len(inventory) < 200_000


class TestReconCaching:
    def test_first_run_generates_and_caches(self, cfg: HarnessConfig, source: Path) -> None:
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            provider = FakeProvider(json.dumps(ARCHITECTURE))
            report = build(cfg, db, provider, FakeCheckouts(source)).run("run1")

            assert report.generated == 1
            assert provider.calls == 1
            cached = db.get_architecture("my-org/service-a", "h1")
            assert cached is not None
            assert cached["content"]["build_targets"][0]["ships_to_prod"] is True

    def test_second_run_with_the_same_structure_hits_the_cache(
        self, cfg: HarnessConfig, source: Path
    ) -> None:
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            provider = FakeProvider(json.dumps(ARCHITECTURE))
            build(cfg, db, provider, FakeCheckouts(source)).run("run1")

            second = FakeProvider(json.dumps(ARCHITECTURE))
            report = build(cfg, db, second, FakeCheckouts(source)).run("run2")

            assert report.cached == 1
            assert report.generated == 0
            assert second.calls == 0

    def test_changed_structure_hash_regenerates(self, cfg: HarnessConfig, source: Path) -> None:
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            build(cfg, db, FakeProvider(json.dumps(ARCHITECTURE)), FakeCheckouts(source)).run(
                "run1"
            )

            db.record_snapshot("my-org/service-a", "sha2", "h2")
            provider = FakeProvider(json.dumps(ARCHITECTURE))
            report = build(cfg, db, provider, FakeCheckouts(source)).run("run2")

            assert report.generated == 1
            assert provider.calls == 1

    def test_new_commit_with_unchanged_structure_does_not_regenerate(
        self, cfg: HarnessConfig, source: Path
    ) -> None:
        """Recon is invalidated by watched-path content, not by every commit."""
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            build(cfg, db, FakeProvider(json.dumps(ARCHITECTURE)), FakeCheckouts(source)).run(
                "run1"
            )

            db.record_snapshot("my-org/service-a", "sha2", "h1")
            provider = FakeProvider(json.dumps(ARCHITECTURE))
            report = build(cfg, db, provider, FakeCheckouts(source)).run("run2")

            assert report.cached == 1
            assert provider.calls == 0


class TestReconCostAmortization:
    def test_cost_is_charged_to_the_repo_not_an_alert(
        self, cfg: HarnessConfig, source: Path
    ) -> None:
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            build(cfg, db, FakeProvider(json.dumps(ARCHITECTURE)), FakeCheckouts(source)).run(
                "run1"
            )
            rows = db.query("SELECT alert_key, stage FROM budget_ledger WHERE run_id='run1'")
            assert rows
            assert all(r["alert_key"] is None and r["stage"] == "recon" for r in rows)

    def test_amortization_falls_with_alert_count(self, cfg: HarnessConfig, source: Path) -> None:
        """The M5 gate: recon cost per alert below 20% of first-alert cost at 10+ alerts."""
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            stage = build(cfg, db, FakeProvider(json.dumps(ARCHITECTURE)), FakeCheckouts(source))
            stage.run("run1")

            first_alert_cost = stage.amortization("my-org/service-a", 1)
            ten_alert_cost = stage.amortization("my-org/service-a", 10)

            assert first_alert_cost > 0
            assert ten_alert_cost <= first_alert_cost * 0.2

    def test_amortization_of_zero_alerts_is_zero(self, cfg: HarnessConfig, source: Path) -> None:
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            stage = build(cfg, db, FakeProvider(json.dumps(ARCHITECTURE)), FakeCheckouts(source))
            assert stage.amortization("my-org/service-a", 0) == 0.0


class TestReconFailureModes:
    def test_checkout_failure_records_a_wish_and_no_architecture(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            report = build(cfg, db, FakeProvider("{}"), FakeCheckouts(None, fail=True)).run("run1")

            assert report.generated == 0
            assert report.repos[0].error
            assert db.get_architecture("my-org/service-a", "h1") is None
            assert any("could not clone" in w["need"] for w in db.open_wishes())

    def test_schema_violating_document_is_rejected(self, cfg: HarnessConfig, source: Path) -> None:
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            bad = json.dumps({"repo": "my-org/service-a", "summary": "x"})
            report = build(cfg, db, FakeProvider(bad), FakeCheckouts(source)).run("run1")

            assert report.generated == 0
            assert "invalid architecture document" in (report.repos[0].error or "")
            assert db.get_architecture("my-org/service-a", "h1") is None

    def test_transient_error_body_is_not_cached_as_an_architecture(
        self, cfg: HarnessConfig, source: Path
    ) -> None:
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            provider = FakeProvider('{"error": {"type": "overloaded_error"}}')
            report = build(cfg, db, provider, FakeCheckouts(source)).run("run1")

            assert report.generated == 0
            assert db.get_architecture("my-org/service-a", "h1") is None

    def test_budget_breach_defers_rather_than_failing_the_run(
        self, cfg: HarnessConfig, source: Path
    ) -> None:
        object.__setattr__(cfg.budgets, "per_repo_usd", 0.0001)
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            db.record_cost(run_id="run1", repo="my-org/service-a", stage="recon", cost_usd=1.0)
            provider = FakeProvider(json.dumps(ARCHITECTURE))
            report = build(cfg, db, provider, FakeCheckouts(source)).run("run1")

            assert provider.calls == 0
            assert "budget" in (report.repos[0].error or "")

    def test_missing_snapshot_is_reported_not_crashed(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            report = build(cfg, db, FakeProvider("{}"), FakeCheckouts(None)).run("run1")
            assert report.repos[0].error == "no snapshot recorded"


class TestGapsBecomeWishes:
    def test_reported_gaps_are_recorded_rather_than_guessed(
        self, cfg: HarnessConfig, source: Path
    ) -> None:
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            build(cfg, db, FakeProvider(json.dumps(ARCHITECTURE)), FakeCheckouts(source)).run(
                "run1"
            )
            wishes = [w["need"] for w in db.open_wishes()]
            assert any("cmd/worker" in w for w in wishes)


class TestPromptContract:
    def test_prompt_is_sent_as_a_cacheable_prefix(self, cfg: HarnessConfig, source: Path) -> None:
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            provider = FakeProvider(json.dumps(ARCHITECTURE))
            build(cfg, db, provider, FakeCheckouts(source)).run("run1")

            assert provider.last_request is not None
            assert provider.last_request.cacheable_prefix
            assert "ships_to_prod" in provider.last_request.cacheable_prefix

    def test_prompt_forbids_guessing(self) -> None:
        prompt = (Path("harness/prompts/recon.md")).read_text()
        assert "Do not guess" in prompt
        assert "gaps" in prompt


class TestCostAttribution:
    def test_recon_cost_excludes_other_stages(self, cfg: HarnessConfig, source: Path) -> None:
        """Total repo spend would inflate both the cached cost and the M5 gate metric."""
        with Database(cfg.storage.db_path) as db:
            db.record_snapshot("my-org/service-a", "sha1", "h1")
            db.record_cost(
                run_id="run1",
                repo="my-org/service-a",
                stage="judgment",
                cost_usd=2.0,
                alert_key="k1",
            )
            stage = build(cfg, db, FakeProvider(json.dumps(ARCHITECTURE)), FakeCheckouts(source))
            report = stage.run("run1")

            assert report.repos[0].cost_usd < 1.0
            cached = db.get_architecture("my-org/service-a", "h1")
            assert cached is not None
            assert cached["cost_usd"] < 1.0
            assert stage.amortization("my-org/service-a", 1) < 1.0
