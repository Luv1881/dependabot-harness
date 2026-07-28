from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from harness.config import HarnessConfig, load_config
from harness.db import AlertRecord, Database
from harness.dedup import InvertedIndex, trivial_clusters
from harness.models import BudgetLedger, ModelClient, ModelRequest, ModelResponse, Usage
from harness.stages.dedup import DedupStage, propagate_verdicts
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


class FakeProvider:
    def __init__(self, text: str) -> None:
        self.text = text
        self.calls = 0
        self.last_request: ModelRequest | None = None

    def complete(self, request: ModelRequest, model: str) -> ModelResponse:
        self.calls += 1
        self.last_request = request
        return ModelResponse(text=self.text, usage=Usage(tokens_in=800, tokens_out=200))


def alert(**kw: Any) -> AlertRecord:
    defaults: dict[str, Any] = dict(
        alert_key="k1",
        repo="my-org/service-a",
        ghsa_id="GHSA-x",
        purl="pkg:golang/github.com/vuln/lib",
        ecosystem="go",
        manifest_path="go.mod",
        gh_alert_num=1,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        state="open",
        resolved_ver="1.0.0",
        patched_ver="1.2.0",
        is_direct=True,
        cvss_score=7.5,
    )
    defaults.update(kw)
    return AlertRecord(**defaults)


@pytest.fixture()
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessConfig:
    monkeypatch.setenv("GH_TOKEN", "ghp_test")
    path = tmp_path / "harness.yaml"
    path.write_text(CONFIG)
    loaded = load_config(path)
    object.__setattr__(loaded.storage, "db_path", tmp_path / "harness.db")
    object.__setattr__(loaded.cache, "dir", tmp_path / "cache")
    return loaded


def seed(db: Database, alerts: list[AlertRecord], run_id: str = "run1") -> None:
    for record in alerts:
        db.upsert_alert(record)
        db.record_stage(run_id=run_id, alert_key=record.alert_key, stage="policy", status="done")


def build(
    cfg: HarnessConfig, db: Database, provider: FakeProvider, *, use_agent: bool = True
) -> DedupStage:
    ledger = BudgetLedger(cfg.budgets, db, "run1")
    client = ModelClient(cfg.model("dedup"), ledger, provider=provider)
    return DedupStage(cfg, db, ledger, client=client, use_agent=use_agent)


class TestInvertedIndex:
    def test_shortlist_is_bounded(self) -> None:
        alerts = [alert(alert_key=f"k{i}") for i in range(50)]
        index = InvertedIndex.build(alerts)
        assert len(index.candidates(alerts[0])) <= 10

    def test_alert_is_not_its_own_candidate(self) -> None:
        alerts = [alert(alert_key="k1"), alert(alert_key="k2")]
        index = InvertedIndex.build(alerts)
        assert "k1" not in index.candidates(alerts[0])

    def test_same_advisory_outranks_same_manifest(self) -> None:
        subject = alert(alert_key="k1", ghsa_id="GHSA-a", purl="pkg:golang/a")
        same_advisory = alert(alert_key="k2", ghsa_id="GHSA-a", purl="pkg:golang/b")
        same_manifest = alert(alert_key="k3", ghsa_id="GHSA-z", purl="pkg:golang/c")
        index = InvertedIndex.build([subject, same_advisory, same_manifest])
        candidates = index.candidates(subject)
        assert candidates.index("k2") < candidates.index("k3")

    def test_shared_symbols_raise_a_candidate(self) -> None:
        subject = alert(alert_key="k1", ghsa_id="GHSA-a", symbols=["lib.Parse"])
        sharer = alert(
            alert_key="k2", ghsa_id="GHSA-b", purl="pkg:golang/other", symbols=["lib.Parse"]
        )
        index = InvertedIndex.build([subject, sharer])
        assert "k2" in index.candidates(subject)

    def test_shortlisting_is_far_cheaper_than_all_pairs(self) -> None:
        alerts = [
            alert(alert_key=f"k{i}", ghsa_id=f"GHSA-{i}", purl=f"pkg:golang/p{i}")
            for i in range(60)
        ]
        index = InvertedIndex.build(alerts)
        all_pairs, shortlisted = index.comparisons_avoided()
        assert all_pairs == 60 * 59 // 2
        assert shortlisted < all_pairs / 2

    def test_index_is_deterministic(self) -> None:
        alerts = [alert(alert_key=f"k{i}", ghsa_id="GHSA-a") for i in range(20)]
        first = InvertedIndex.build(alerts).candidates(alerts[0])
        second = InvertedIndex.build(alerts).candidates(alerts[0])
        assert first == second


class TestTrivialClusters:
    def test_same_advisory_and_package_clusters_without_a_model(self) -> None:
        alerts = [
            alert(alert_key="k1", manifest_path="services/a/go.mod"),
            alert(alert_key="k2", manifest_path="services/b/go.mod"),
        ]
        clusters = trivial_clusters(InvertedIndex.build(alerts))
        assert len(clusters) == 1
        assert set(clusters[0].members) == {"k1", "k2"}

    def test_different_packages_do_not_cluster(self) -> None:
        alerts = [
            alert(alert_key="k1", purl="pkg:golang/a"),
            alert(alert_key="k2", purl="pkg:golang/b"),
        ]
        assert trivial_clusters(InvertedIndex.build(alerts)) == []

    def test_canonical_prefers_a_direct_dependency(self) -> None:
        alerts = [
            alert(alert_key="k1", is_direct=False, cvss_score=9.0),
            alert(alert_key="k2", is_direct=True, cvss_score=5.0),
        ]
        assert trivial_clusters(InvertedIndex.build(alerts))[0].canonical == "k2"

    def test_canonical_prefers_higher_severity_among_equals(self) -> None:
        alerts = [
            alert(alert_key="k1", is_direct=True, cvss_score=5.0),
            alert(alert_key="k2", is_direct=True, cvss_score=9.0),
        ]
        assert trivial_clusters(InvertedIndex.build(alerts))[0].canonical == "k2"


class TestDedupStage:
    def test_trivial_clusters_need_no_agent_call(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(
                db,
                [
                    alert(alert_key="k1", manifest_path="a/go.mod"),
                    alert(alert_key="k2", manifest_path="b/go.mod"),
                ],
            )
            provider = FakeProvider('{"clusters": []}')
            report = build(cfg, db, provider).run("run1")

            assert report.clusters == 1
            assert report.suppressed == 1
            assert provider.calls == 0

    def test_suppressed_members_are_skipped_and_named(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(
                db,
                [
                    alert(alert_key="k1", manifest_path="a/go.mod", is_direct=True),
                    alert(alert_key="k2", manifest_path="b/go.mod", is_direct=False),
                ],
            )
            build(cfg, db, FakeProvider('{"clusters": []}')).run("run1")

            assert db.stage_status("run1", "k1", "dedup") == "done"
            assert db.stage_status("run1", "k2", "dedup") == "skipped"
            payload = db.stage_payload("run1", "k2", "dedup")
            assert payload["inherits_from"] == "k1"

    def test_unclustered_alerts_stay_eligible_for_judgment(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, [alert(alert_key="k1", ghsa_id="GHSA-a", purl="pkg:golang/a")])
            build(cfg, db, FakeProvider('{"clusters": []}')).run("run1")
            assert db.stage_status("run1", "k1", "dedup") == "done"

    def test_clustering_reduces_judgment_invocations(self, cfg: HarnessConfig) -> None:
        """The M9 accept metric."""
        with Database(cfg.storage.db_path) as db:
            alerts = [alert(alert_key=f"k{i}", manifest_path=f"svc{i}/go.mod") for i in range(6)]
            seed(db, alerts)
            report = build(cfg, db, FakeProvider('{"clusters": []}')).run("run1")

            assert report.alerts == 6
            assert report.judgment_invocations_saved == 5

    def test_agent_cluster_is_accepted_when_well_formed(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(
                db,
                [
                    alert(alert_key="k1", ghsa_id="GHSA-a", purl="pkg:golang/parent"),
                    alert(alert_key="k2", ghsa_id="GHSA-b", purl="pkg:golang/child"),
                ],
            )
            payload = {
                "clusters": [
                    {
                        "canonical": "k1",
                        "members": ["k1", "k2"],
                        "rationale": "bumping the parent resolves the child",
                    }
                ]
            }
            report = build(cfg, db, FakeProvider(json.dumps(payload))).run("run1")

            assert report.clusters == 1
            assert report.suppressed == 1


class TestAgentClustersAreValidated:
    def test_cluster_naming_an_unseen_alert_is_discarded(self, cfg: HarnessConfig) -> None:
        """An invented member would suppress analysis of an alert nobody reasoned about."""
        with Database(cfg.storage.db_path) as db:
            seed(
                db,
                [
                    alert(alert_key="k1", ghsa_id="GHSA-a", purl="pkg:golang/a"),
                    alert(alert_key="k2", ghsa_id="GHSA-b", purl="pkg:golang/b"),
                ],
            )
            payload = {"clusters": [{"canonical": "k1", "members": ["k1", "ghost"]}]}
            report = build(cfg, db, FakeProvider(json.dumps(payload))).run("run1")

            assert report.clusters == 0
            assert report.suppressed == 0

    def test_canonical_outside_members_is_discarded(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(
                db,
                [
                    alert(alert_key="k1", ghsa_id="GHSA-a", purl="pkg:golang/a"),
                    alert(alert_key="k2", ghsa_id="GHSA-b", purl="pkg:golang/b"),
                ],
            )
            payload = {"clusters": [{"canonical": "k3", "members": ["k1", "k2"]}]}
            report = build(cfg, db, FakeProvider(json.dumps(payload))).run("run1")
            assert report.clusters == 0

    def test_single_member_cluster_is_discarded(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, [alert(alert_key="k1"), alert(alert_key="k2", purl="pkg:golang/b")])
            payload = {"clusters": [{"canonical": "k1", "members": ["k1"]}]}
            report = build(cfg, db, FakeProvider(json.dumps(payload))).run("run1")
            assert report.clusters == 0

    def test_malformed_agent_response_clusters_nothing(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, [alert(alert_key="k1"), alert(alert_key="k2", purl="pkg:golang/b")])
            report = build(cfg, db, FakeProvider("not json at all")).run("run1")
            assert report.clusters == 0
            assert report.errors


class TestVerdictPropagation:
    def test_members_inherit_and_the_source_is_named(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(
                db,
                [
                    alert(alert_key="k1", manifest_path="a/go.mod", is_direct=True),
                    alert(alert_key="k2", manifest_path="b/go.mod", is_direct=False),
                ],
            )
            build(cfg, db, FakeProvider('{"clusters": []}')).run("run1")
            db.put_verdict(
                alert_key="k1",
                run_id="run1",
                verdict={"alert_key": "k1", "verdict": "affected", "confidence": 0.8},
                validated=True,
                structure_hash="h1",
            )

            assert propagate_verdicts(db, "run1") == 1
            inherited = db.latest_verdict("k2")
            assert inherited["verdict"]["verdict"] == "affected"
            assert inherited["verdict"]["inherited_from"] == "k1"
            assert inherited["verdict"]["decided_by"] == "dedup_inheritance"

    def test_nothing_propagates_without_a_canonical_verdict(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(
                db,
                [
                    alert(alert_key="k1", manifest_path="a/go.mod"),
                    alert(alert_key="k2", manifest_path="b/go.mod"),
                ],
            )
            build(cfg, db, FakeProvider('{"clusters": []}')).run("run1")
            assert propagate_verdicts(db, "run1") == 0
            assert db.latest_verdict("k2") is None


class TestPromptContract:
    def test_prompt_asks_one_narrow_question(self) -> None:
        prompt = Path("harness/prompts/dedup.md").read_text()
        assert "Would a single dependency change close all of these?" in prompt

    def test_prompt_warns_against_over_eager_clustering(self) -> None:
        prompt = Path("harness/prompts/dedup.md").read_text()
        assert "leave them unclustered" in prompt
        assert "silently dismissed" in prompt


class TestClusteringRespectsUpgradePaths:
    def test_different_major_versions_do_not_cluster(self) -> None:
        """1.x and 2.x are separate upgrade paths with different reachability."""
        alerts = [
            alert(alert_key="k1", resolved_ver="1.4.2", patched_ver="1.4.9"),
            alert(alert_key="k2", resolved_ver="2.1.0", patched_ver="2.1.5"),
        ]
        assert trivial_clusters(InvertedIndex.build(alerts)) == []

    def test_different_target_versions_do_not_cluster(self) -> None:
        alerts = [
            alert(alert_key="k1", resolved_ver="1.0.0", patched_ver="1.2.0"),
            alert(alert_key="k2", resolved_ver="1.0.0", patched_ver="1.9.0"),
        ]
        assert trivial_clusters(InvertedIndex.build(alerts)) == []

    def test_identical_upgrade_path_still_clusters(self) -> None:
        alerts = [
            alert(alert_key="k1", manifest_path="a/go.mod", resolved_ver="1.0.0"),
            alert(alert_key="k2", manifest_path="b/go.mod", resolved_ver="1.0.0"),
        ]
        clusters = trivial_clusters(InvertedIndex.build(alerts))
        assert len(clusters) == 1
        assert set(clusters[0].members) == {"k1", "k2"}


class TestInheritedVerdictsAreNeverAutoDismissed:
    def test_validator_agreement_does_not_transfer(self, cfg: HarnessConfig) -> None:
        """The validator examined the canonical alert, not this one."""
        with Database(cfg.storage.db_path) as db:
            seed(
                db,
                [
                    alert(alert_key="k1", manifest_path="a/go.mod", is_direct=True),
                    alert(alert_key="k2", manifest_path="b/go.mod", is_direct=False),
                ],
            )
            build(cfg, db, FakeProvider('{"clusters": []}')).run("run1")
            db.put_verdict(
                alert_key="k1",
                run_id="run1",
                verdict={
                    "alert_key": "k1",
                    "verdict": "not_affected",
                    "vex_justification": "vulnerable_code_not_in_execute_path",
                    "confidence": 0.95,
                    "needs_human": False,
                },
                validated=True,
                validator_notes="validator agreed",
                structure_hash="h1",
            )
            propagate_verdicts(db, "run1")

            inherited = db.latest_verdict("k2")
            assert inherited["validated"] is None
            assert "did not examine this alert" in inherited["validator_notes"]

    def test_inherited_verdict_is_blocked_by_the_dismissal_gate(self, cfg: HarnessConfig) -> None:
        from harness.emit.dismissal import DismissalGate

        gate = DismissalGate(
            enabled=True,
            requirements={
                "verdict": "not_affected",
                "confidence_min": 0.85,
                "validator_agreed": True,
            },
        )
        inherited = {
            "verdict": "not_affected",
            "vex_justification": "vulnerable_code_not_in_execute_path",
            "confidence": 0.95,
            "needs_human": False,
            "decided_by": "dedup_inheritance",
        }
        decision = gate.evaluate(inherited, None)
        assert not decision.allowed
        assert "unconfirmed" in decision.blocked_by
