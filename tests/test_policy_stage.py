from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from harness.config import HarnessConfig, load_config, load_policy
from harness.db import AlertRecord, Database
from harness.policy import PolicyEngine
from harness.sources.checkout import Checkout, CheckoutError
from harness.stages.policy import PolicyStage
from harness.util import utcnow

CONFIG = """
github:
  org: my-org
  repos: [my-org/service-a]
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


def seed(db: Database, run_id: str, **kw: Any) -> AlertRecord:
    defaults: dict[str, Any] = dict(
        alert_key=kw.pop("alert_key", "k1"),
        repo="my-org/service-a",
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        purl="pkg:golang/github.com/vuln/lib",
        ecosystem="go",
        manifest_path="go.mod",
        gh_alert_num=1,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        state="open",
        resolved_ver="0.3.1",
        patched_ver="0.3.4",
        dep_scope="runtime",
        is_direct=True,
        cvss_score=7.5,
        in_kev=False,
    )
    defaults.update(kw)
    record = AlertRecord(**defaults)
    db.upsert_alert(record)
    db.record_stage(run_id=run_id, alert_key=record.alert_key, stage="ingest", status="done")
    db.record_snapshot("my-org/service-a", "sha1", "h1")
    return record


def build(cfg: HarnessConfig, db: Database, checkouts: FakeCheckouts) -> PolicyStage:
    return PolicyStage(
        cfg, db, PolicyEngine(load_policy("config/policy.yaml")), checkouts=checkouts
    )


class TestStageWiring:
    def test_cleared_alert_is_skipped_and_gets_a_verdict(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            record = seed(db, "run1", resolved_ver="1.0.0")
            build(cfg, db, FakeCheckouts(None)).run("run1")

            assert db.stage_status("run1", record.alert_key, "policy") == "skipped"
            verdict = db.latest_verdict(record.alert_key)
            assert verdict is not None
            assert verdict["verdict"]["verdict"] == "fixed"
            assert verdict["verdict"]["decided_by"] == "policy"
            assert verdict["structure_hash"] == "h1"

    def test_uncleared_alert_is_done_with_no_verdict(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            record = seed(db, "run1", resolved_ver="0.3.1", patched_ver="0.9.0")
            build(cfg, db, FakeCheckouts(None)).run("run1")

            assert db.stage_status("run1", record.alert_key, "policy") == "done"
            assert db.latest_verdict(record.alert_key) is None

    def test_dedup_outcome_writes_no_verdict(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            first = seed(db, "run1", alert_key="k1", patched_ver="0.3.4")
            seed(db, "run1", alert_key="k2", ghsa_id="GHSA-newer", patched_ver="9.9.9")

            build(cfg, db, FakeCheckouts(None)).run("run1")

            payload = db.stage_payload("run1", first.alert_key, "policy")
            assert payload["kind"] == "dedup"
            assert db.latest_verdict(first.alert_key) is None

    def test_alert_without_completed_ingest_is_not_evaluated(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            record = seed(db, "run1", resolved_ver="1.0.0")
            db.record_stage(
                run_id="run1", alert_key=record.alert_key, stage="ingest", status="failed"
            )
            report = build(cfg, db, FakeCheckouts(None)).run("run1")
            assert report.stats.total == 0
            assert db.stage_status("run1", record.alert_key, "policy") is None


class TestCheckoutDegradation:
    def test_checkout_failure_is_recorded_and_not_a_clearance(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            record = seed(db, "run1", resolved_ver="0.3.1", patched_ver="0.9.0")
            report = build(cfg, db, FakeCheckouts(None, fail=True)).run("run1")

            assert report.checkout_failures
            assert db.stage_status("run1", record.alert_key, "policy") == "done"
            assert db.latest_verdict(record.alert_key) is None

    def test_not_imported_fires_with_a_real_checkout(
        self, cfg: HarnessConfig, tmp_path: Path
    ) -> None:
        source = tmp_path / "src"
        source.mkdir()
        (source / "main.go").write_text('package main\nimport "fmt"\n')

        with Database(cfg.storage.db_path) as db:
            record = seed(db, "run1", resolved_ver="0.3.1", patched_ver="0.9.0")
            build(cfg, db, FakeCheckouts(source)).run("run1")

            payload = db.stage_payload("run1", record.alert_key, "policy")
            assert payload["rule_id"] == "not_imported"
            assert db.latest_verdict(record.alert_key)["verdict"]["verdict"] == "not_affected"


class TestResume:
    def test_completed_policy_stage_is_not_re_evaluated(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, "run1", resolved_ver="1.0.0")
            first = build(cfg, db, FakeCheckouts(None)).run("run1")
            assert first.stats.cleared == 1

            resumed = build(cfg, db, FakeCheckouts(None)).run("run1")
            assert resumed.stats.total == 1
            assert resumed.stats.by_rule["already_fixed"] == 1

    def test_stats_survive_resume_for_uncleared_alerts(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, "run1", resolved_ver="0.3.1", patched_ver="0.9.0")
            build(cfg, db, FakeCheckouts(None)).run("run1")
            resumed = build(cfg, db, FakeCheckouts(None)).run("run1")

            assert resumed.stats.total == 1
            assert resumed.stats.cleared == 0
            assert resumed.stats.reaching_analysis == 1


class TestArchitectureAwareness:
    def test_dev_only_uses_build_targets_when_cached(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            record = seed(db, "run1", dep_scope="development")
            db.put_architecture(
                repo="my-org/service-a",
                commit_sha="sha1",
                structure_hash="h1",
                content={
                    "build_targets": [{"name": "api", "entry": "cmd/api", "ships_to_prod": True}]
                },
                cost_usd=0.0,
            )
            build(cfg, db, FakeCheckouts(None)).run("run1")

            payload = db.stage_payload("run1", record.alert_key, "policy")
            assert payload["rule_id"] == "dev_only"
            assert payload["detail"]["variant"] == "build_targets_checked"

    def test_dev_only_declines_without_architecture(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            record = seed(db, "run1", dep_scope="development", patched_ver="0.9.0")
            build(cfg, db, FakeCheckouts(None)).run("run1")

            payload = db.stage_payload("run1", record.alert_key, "policy")
            assert payload["rule_id"] != "dev_only"
            assert db.latest_verdict(record.alert_key) is None


class TestStageHandoffSemantics:
    """`done` means no rule matched, `skipped` means a rule terminated the alert.

    The evidence stage gates on `done`, so conflating the two would either analyze
    already-decided alerts or silently drop undecided ones.
    """

    def test_done_is_written_only_when_no_rule_matched(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            undecided = seed(db, "run1", alert_key="k1", resolved_ver="0.3.1", patched_ver="0.9.0")
            cleared = seed(db, "run1", alert_key="k2", resolved_ver="1.0.0")
            build(cfg, db, FakeCheckouts(None)).run("run1")

            assert db.stage_status("run1", undecided.alert_key, "policy") == "done"
            assert db.stage_payload("run1", undecided.alert_key, "policy")["rule_id"] is None
            assert db.stage_status("run1", cleared.alert_key, "policy") == "skipped"
            assert db.stage_payload("run1", cleared.alert_key, "policy")["rule_id"] is not None
