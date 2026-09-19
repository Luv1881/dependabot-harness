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

    def test_superseded_alert_is_decided_and_written(self, cfg: HarnessConfig) -> None:
        """It used to be recorded as `dedup` with no verdict at all, so a superseded alert
        produced no VEX statement, no SARIF finding, and no dismissal — while still being
        counted in the cleared percentage."""
        with Database(cfg.storage.db_path) as db:
            first = seed(db, "run1", alert_key="k1", patched_ver="0.3.4")
            seed(db, "run1", alert_key="k2", ghsa_id="GHSA-newer", patched_ver="9.9.9")

            build(cfg, db, FakeCheckouts(None)).run("run1")

            payload = db.stage_payload("run1", first.alert_key, "policy")
            assert payload["kind"] == "skip_analysis"
            assert payload["verdict"] == "affected"
            stored = db.latest_verdict(first.alert_key)
            assert stored is not None, "a superseded alert must still carry a verdict"
            verdict = stored["verdict"]
            assert verdict["verdict"] == "affected"
            assert "9.9.9" in verdict["recommended_action"]

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


class TestConfidenceIsHeldToTheEcosystemCeiling:
    """A policy rule is certain of its fact; the conclusion is only as reliable as the
    ecosystem's tooling. The ceiling is declared per ecosystem and enforced in the
    validation stage — which a policy-cleared alert never reaches, so it has to be applied
    where the verdict is written.

    On a real npm repository this produced 135 `not_affected` verdicts at confidence 1.0
    against a declared ceiling of 0.55, comfortably over an
    `auto_dismiss_requires.confidence_min` of 0.85.
    """

    def test_an_npm_clearance_cannot_exceed_the_npm_ceiling(
        self, cfg: HarnessConfig, tmp_path: Path
    ) -> None:
        root = tmp_path / "src"
        (root / "src").mkdir(parents=True)
        (root / "package.json").write_text("{}")
        (root / "src" / "app.js").write_text("const x = require('express');\n")

        with Database(cfg.storage.db_path) as db:
            record = seed(
                db,
                "run1",
                alert_key="npm1",
                ecosystem="npm",
                purl="pkg:npm/lodash",
                manifest_path="package.json",
                resolved_ver="4.17.20",
                patched_ver="4.17.21",
            )
            build(cfg, db, FakeCheckouts(root)).run("run1")

            stored = db.latest_verdict(record.alert_key)
            assert stored is not None
            verdict = stored["verdict"]
            assert verdict["verdict"] == "not_affected"
            assert verdict["confidence"] <= 0.55

    def test_a_go_clearance_keeps_the_roomier_go_ceiling(
        self, cfg: HarnessConfig, tmp_path: Path
    ) -> None:
        root = tmp_path / "src"
        (root / "src").mkdir(parents=True)
        (root / "go.mod").write_text("module m\n")
        (root / "src" / "main.go").write_text("package main\n")

        with Database(cfg.storage.db_path) as db:
            record = seed(db, "run1", alert_key="go1")
            build(cfg, db, FakeCheckouts(root)).run("run1")
            stored = db.latest_verdict(record.alert_key)
            assert stored is not None
            assert stored["verdict"]["confidence"] == 0.95


class TestRuleOrdering:
    """Ordered by what the fact establishes, not by convenience."""

    def test_a_known_exploited_critical_is_never_consolidated_away(
        self, cfg: HarnessConfig, tmp_path: Path
    ) -> None:
        """`superseded` used to run first, so a KEV-listed direct critical with a newer
        sibling advisory was quietly folded into that sibling instead of escalated."""
        with Database(cfg.storage.db_path) as db:
            a = seed(
                db,
                "run1",
                alert_key="kev1",
                in_kev=True,
                is_direct=True,
                cvss_score=9.9,
                patched_ver="1.0.0",
            )
            seed(db, "run1", alert_key="kev2", ghsa_id="GHSA-newer", patched_ver="9.9.9")

            build(cfg, db, FakeCheckouts(None)).run("run1")

            payload = db.stage_payload("run1", a.alert_key, "policy")
            assert payload["rule_id"] == "kev_direct_critical"
            assert payload["verdict"] == "affected"
            assert payload["needs_human"] is True

    def test_a_package_level_clearance_wins_over_per_advisory_consolidation(
        self, cfg: HarnessConfig, tmp_path: Path
    ) -> None:
        """If nothing imports the package, no advisory on it is reachable — a fact valid
        for every advisory at once, and therefore stronger than a per-advisory note that a
        newer sibling exists."""
        root = tmp_path / "src"
        (root / "src").mkdir(parents=True)
        (root / "go.mod").write_text("module m\n")
        (root / "src" / "main.go").write_text("package main\n")

        with Database(cfg.storage.db_path) as db:
            a = seed(db, "run1", alert_key="ni1", purl="pkg:golang/github.com/never/used")
            seed(
                db,
                "run1",
                alert_key="ni2",
                ghsa_id="GHSA-newer",
                purl="pkg:golang/github.com/never/used",
                patched_ver="9.9.9",
            )
            build(cfg, db, FakeCheckouts(root)).run("run1")

            payload = db.stage_payload("run1", a.alert_key, "policy")
            assert payload["rule_id"] == "not_imported"
            assert payload["verdict"] == "not_affected"


class TestTheConfidenceClamp:
    @pytest.mark.parametrize(
        ("ecosystem", "ceiling"),
        [("go", 0.95), ("cargo", 0.90), ("pip", 0.75), ("maven", 0.70), ("npm", 0.55)],
    )
    def test_it_matches_the_adapter(self, ecosystem: str, ceiling: float) -> None:
        from harness.policy import policy_confidence

        assert policy_confidence(ecosystem) == ceiling

    def test_an_unknown_ecosystem_gets_no_benefit_of_the_doubt(self) -> None:
        from harness.policy import CONFIDENCE_WHEN_ECOSYSTEM_UNKNOWN, policy_confidence

        assert policy_confidence("some-new-ecosystem") == CONFIDENCE_WHEN_ECOSYSTEM_UNKNOWN

    def test_it_never_exceeds_one(self) -> None:
        from harness.policy import policy_confidence

        assert policy_confidence("go") <= 1.0
