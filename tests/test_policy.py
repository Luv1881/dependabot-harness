from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from harness.analysis.imports import ImportIndex
from harness.config import load_policy
from harness.db import AlertRecord
from harness.policy import PolicyEngine, PolicyError, RuleContext
from harness.policy.context import OutcomeKind
from harness.util import utcnow

POLICY = load_policy("config/policy.yaml")


@dataclass
class StubFacts:
    index: ImportIndex = field(default_factory=lambda: ImportIndex.unavailable("stub"))
    targets: list[str] | None = None
    superseding: str | None = None

    def import_index(self, ecosystem: str) -> ImportIndex:
        return self.index

    def production_build_targets(self) -> list[str] | None:
        return self.targets

    def newer_advisory_for(self, alert: AlertRecord) -> str | None:
        return self.superseding


def alert(**kw: Any) -> AlertRecord:
    defaults: dict[str, Any] = dict(
        alert_key="k1",
        repo="org/repo",
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
        severity="high",
        in_kev=False,
    )
    defaults.update(kw)
    return AlertRecord(**defaults)


def evaluate(engine: PolicyEngine, record: AlertRecord, facts: StubFacts | None = None):
    return engine.evaluate(RuleContext(alert=record, facts=facts or StubFacts()))


@pytest.fixture()
def engine() -> PolicyEngine:
    return PolicyEngine(POLICY)


class TestEngineConstruction:
    def test_all_configured_rules_have_implementations(self, engine: PolicyEngine) -> None:
        configured = {r["id"] for r in POLICY["rules"]}
        assert {r.id for r in engine.rules} == configured

    def test_unknown_rule_id_fails_loudly(self) -> None:
        with pytest.raises(PolicyError, match="no implementation"):
            PolicyEngine({"rules": [{"id": "does_not_exist"}]})

    def test_rule_order_is_config_order(self, engine: PolicyEngine) -> None:
        assert [r.id for r in engine.rules] == [r["id"] for r in POLICY["rules"]]


class TestAlreadyFixed:
    def test_resolved_at_patched(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(resolved_ver="0.3.4", patched_ver="0.3.4"))
        assert outcome is not None
        assert outcome.rule_id == "already_fixed"
        assert outcome.verdict == "fixed"

    def test_resolved_above_patched(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(resolved_ver="1.0.0", patched_ver="0.3.4"))
        assert outcome is not None and outcome.rule_id == "already_fixed"

    def test_declines_when_below(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(resolved_ver="0.3.1", patched_ver="0.3.4"))
        assert outcome is None or outcome.rule_id != "already_fixed"

    def test_declines_when_version_unparsable(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(resolved_ver=None, patched_ver="0.3.4"))
        assert outcome is None or outcome.rule_id != "already_fixed"


class TestSuperseded:
    def test_emits_dedup_kind_not_a_verdict(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(), StubFacts(superseding="GHSA-newer"))
        assert outcome is not None
        assert outcome.kind is OutcomeKind.DEDUP
        assert outcome.verdict is None
        assert outcome.detail["superseded_by"] == "GHSA-newer"


class TestKevDirectCritical:
    def test_escalates(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(in_kev=True, is_direct=True, cvss_score=9.8))
        assert outcome is not None
        assert outcome.rule_id == "kev_direct_critical"
        assert outcome.kind is OutcomeKind.ESCALATE
        assert outcome.needs_human is True

    def test_declines_below_threshold(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(in_kev=True, is_direct=True, cvss_score=8.9))
        assert outcome is None or outcome.rule_id != "kev_direct_critical"

    def test_declines_when_transitive(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(in_kev=True, is_direct=False, cvss_score=9.8))
        assert outcome is None or outcome.rule_id != "kev_direct_critical"

    def test_declines_when_directness_unknown(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(in_kev=True, is_direct=None, cvss_score=9.8))
        assert outcome is None or outcome.rule_id != "kev_direct_critical"


class TestDevOnly:
    def test_declines_without_architecture_when_scope_is_not_conclusive(
        self, engine: PolicyEngine
    ) -> None:
        outcome = evaluate(engine, alert(dep_scope="development"), StubFacts(targets=None))
        assert outcome is None or outcome.rule_id != "dev_only"

    def test_full_check_when_architecture_present(self, engine: PolicyEngine) -> None:
        facts = StubFacts(targets=["cmd/api"])
        outcome = evaluate(engine, alert(dep_scope="development"), facts)
        assert outcome is not None
        assert outcome.detail["variant"] == "build_targets_checked"

    def test_declines_when_in_a_production_target(self, engine: PolicyEngine) -> None:
        facts = StubFacts(targets=["go.mod"])
        outcome = evaluate(engine, alert(dep_scope="development"), facts)
        assert outcome is None or outcome.rule_id != "dev_only"

    def test_declines_for_runtime_scope(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(dep_scope="runtime"))
        assert outcome is None or outcome.rule_id != "dev_only"

    def test_declines_for_unknown_scope(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(dep_scope="unknown"))
        assert outcome is None or outcome.rule_id != "dev_only"

    def test_justification_is_a_cisa_code(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(dep_scope="development"), StubFacts(targets=["cmd/api"]))
        assert outcome is not None
        assert outcome.rule_id == "dev_only"
        assert outcome.vex_justification in POLICY["valid_vex_justifications"]


class TestNotImported:
    def test_fires_when_package_absent_from_scanned_repo(self, engine: PolicyEngine) -> None:
        facts = StubFacts(index=ImportIndex(scanned=True, modules={"fmt"}, files_scanned=12))
        outcome = evaluate(engine, alert(), facts)
        assert outcome is not None
        assert outcome.rule_id == "not_imported"
        assert outcome.vex_justification == "vulnerable_code_not_present"

    def test_declines_when_imported(self, engine: PolicyEngine) -> None:
        facts = StubFacts(
            index=ImportIndex(scanned=True, modules={"github.com/vuln/lib"}, files_scanned=3)
        )
        outcome = evaluate(engine, alert(), facts)
        assert outcome is None or outcome.rule_id != "not_imported"

    def test_declines_when_scan_unavailable(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(), StubFacts(index=ImportIndex.unavailable("no checkout")))
        assert outcome is None or outcome.rule_id != "not_imported"

    def test_subpackage_import_counts_as_imported(self, engine: PolicyEngine) -> None:
        facts = StubFacts(
            index=ImportIndex(scanned=True, modules={"github.com/vuln/lib/parser"}, files_scanned=1)
        )
        outcome = evaluate(engine, alert(), facts)
        assert outcome is None or outcome.rule_id != "not_imported"


class TestTrivialPatch:
    def test_patch_bump_skips_analysis(self, engine: PolicyEngine) -> None:
        facts = StubFacts(
            index=ImportIndex(scanned=True, modules={"github.com/vuln/lib"}, files_scanned=1)
        )
        outcome = evaluate(engine, alert(resolved_ver="0.3.1", patched_ver="0.3.4"), facts)
        assert outcome is not None
        assert outcome.rule_id == "trivial_patch"
        assert outcome.kind is OutcomeKind.SKIP_ANALYSIS
        assert outcome.verdict == "affected"

    def test_minor_bump_reaches_analysis(self, engine: PolicyEngine) -> None:
        facts = StubFacts(
            index=ImportIndex(scanned=True, modules={"github.com/vuln/lib"}, files_scanned=1)
        )
        outcome = evaluate(engine, alert(resolved_ver="0.3.1", patched_ver="0.4.0"), facts)
        assert outcome is None


class TestPrecedence:
    def test_already_fixed_wins_over_kev(self, engine: PolicyEngine) -> None:
        outcome = evaluate(
            engine,
            alert(resolved_ver="1.0.0", patched_ver="0.3.4", in_kev=True, cvss_score=9.9),
        )
        assert outcome is not None and outcome.rule_id == "already_fixed"

    def test_kev_wins_over_dev_only(self, engine: PolicyEngine) -> None:
        outcome = evaluate(
            engine,
            alert(dep_scope="development", in_kev=True, is_direct=True, cvss_score=9.9),
        )
        assert outcome is not None and outcome.rule_id == "kev_direct_critical"


class TestClearanceStats:
    def test_percentages_per_rule(self, engine: PolicyEngine) -> None:
        evaluate(engine, alert(resolved_ver="1.0.0"))
        evaluate(engine, alert(resolved_ver="1.0.0"))
        evaluate(engine, alert(dep_scope="development"))
        evaluate(engine, alert(resolved_ver="0.3.1", patched_ver="0.9.0"))

        stats = engine.stats
        assert stats.total == 4
        assert stats.cleared == 3
        assert stats.reaching_analysis == 1
        assert stats.by_rule["already_fixed"] == 2
        assert stats.percentages()["already_fixed"] == 50.0
        assert stats.to_dict()["cleared_pct"] == 75.0

    def test_empty_stats_do_not_divide_by_zero(self, engine: PolicyEngine) -> None:
        assert engine.stats.to_dict()["cleared_pct"] == 0.0
        assert engine.stats.percentages() == {}


class TestOutcomeValidation:
    def test_not_affected_requires_justification(self) -> None:
        bad = {
            "rules": [
                {
                    "id": "dev_only",
                    "when": {},
                    "outcome": {
                        "kind": "verdict",
                        "verdict": "not_affected",
                        "vex_status": "not_affected",
                        "reason": "x",
                    },
                }
            ],
            "valid_vex_justifications": ["component_not_present"],
        }
        engine = PolicyEngine(bad)
        with pytest.raises(PolicyError, match="requires a justification"):
            evaluate(engine, alert(dep_scope="development"), StubFacts(targets=["cmd/api"]))

    def test_non_cisa_justification_rejected(self) -> None:
        bad = {
            "rules": [
                {
                    "id": "dev_only",
                    "when": {},
                    "outcome": {
                        "kind": "verdict",
                        "verdict": "not_affected",
                        "vex_status": "not_affected",
                        "vex_justification": "made_up_code",
                        "reason": "x",
                    },
                }
            ],
            "valid_vex_justifications": ["component_not_present"],
        }
        engine = PolicyEngine(bad)
        with pytest.raises(PolicyError, match="not a CISA code"):
            evaluate(engine, alert(dep_scope="development"), StubFacts(targets=["cmd/api"]))


class TestUndecidableNeverClears:
    """Regression guards: every unmeasured input must decline, not clear."""

    def test_dev_only_declines_when_bundler_could_include_it(self, engine: PolicyEngine) -> None:
        record = alert(
            ecosystem="npm",
            purl="pkg:npm/lodash",
            dep_scope="development",
            resolved_ver="4.17.20",
            patched_ver="4.17.21",
        )
        outcome = evaluate(engine, record, StubFacts(targets=None))
        assert outcome is None or outcome.rule_id != "dev_only"

    def test_dev_only_clears_when_build_system_excludes_the_scope(
        self, engine: PolicyEngine
    ) -> None:
        record = alert(
            ecosystem="maven",
            purl="pkg:maven/junit/junit",
            dep_scope="development",
            resolved_ver="4.12",
            patched_ver="4.13.2",
        )
        outcome = evaluate(engine, record, StubFacts(targets=None))
        assert outcome is not None
        assert outcome.rule_id == "dev_only"
        assert outcome.detail["variant"] == "scope_conclusive"

    def test_not_imported_declines_for_maven(self, engine: PolicyEngine) -> None:
        record = alert(
            ecosystem="maven",
            purl="pkg:maven/com.fasterxml.jackson.core/jackson-databind",
            resolved_ver="2.9.0",
            patched_ver="2.99.0",
        )
        facts = StubFacts(
            index=ImportIndex(
                scanned=True,
                modules={"com.fasterxml.jackson.databind.ObjectMapper"},
                files_scanned=5,
            )
        )
        outcome = evaluate(engine, record, facts)
        assert outcome is None

    def test_not_imported_declines_for_unsupported_ecosystem(self, engine: PolicyEngine) -> None:
        record = alert(
            ecosystem="cocoapods",
            purl="pkg:cocoapods/AFNetworking",
            resolved_ver="3.0.0",
            patched_ver="9.9.9",
        )
        facts = StubFacts(index=ImportIndex(scanned=True, modules=set(), files_scanned=3))
        assert evaluate(engine, record, facts) is None


class TestSupersededDeterminism:
    def test_highest_patched_version_wins_regardless_of_row_order(self) -> None:
        import tempfile

        from harness.db import Database
        from harness.policy import RepoFactsProvider

        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f"{tmp}/h.db")
            base = dict(
                repo="org/repo",
                purl="pkg:golang/github.com/vuln/lib",
                ecosystem="go",
                manifest_path="go.mod",
                gh_alert_num=1,
                first_seen_at=utcnow(),
                last_seen_at=utcnow(),
                state="open",
            )
            for key, ghsa, patched in [
                ("a", "GHSA-zzzz", "1.0.0"),
                ("b", "GHSA-aaaa", "3.0.0"),
                ("c", "GHSA-mmmm", "2.0.0"),
            ]:
                db.upsert_alert(
                    AlertRecord(alert_key=key, ghsa_id=ghsa, patched_ver=patched, **base)
                )

            facts = RepoFactsProvider(repo="org/repo", db=db)
            subject = AlertRecord(
                alert_key="s", ghsa_id="GHSA-subject", patched_ver="0.5.0", **base
            )
            assert facts.newer_advisory_for(subject) == "GHSA-aaaa"
            db.close()


class TestVerdictShapeValidation:
    def test_terminating_outcome_without_a_verdict_is_rejected(self) -> None:
        bad = {
            "rules": [
                {
                    "id": "already_fixed",
                    "outcome": {"kind": "verdict", "reason": "x"},
                }
            ]
        }
        engine = PolicyEngine(bad)
        with pytest.raises(PolicyError, match="must carry a verdict"):
            evaluate(engine, alert(resolved_ver="1.0.0", patched_ver="0.3.4"))

    def test_dedup_outcome_may_omit_a_verdict(self, engine: PolicyEngine) -> None:
        outcome = evaluate(engine, alert(), StubFacts(superseding="GHSA-newer"))
        assert outcome is not None
        assert outcome.verdict is None
