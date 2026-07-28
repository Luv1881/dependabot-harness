from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from harness.config import load_policy
from harness.evaluation import (
    DeterministicPredictor,
    EvalReport,
    GoldenCase,
    GoldenSet,
    Label,
    Outcome,
    Prediction,
    Split,
    compare,
    evaluate,
    load_golden,
)
from harness.evaluation.dataset import DatasetError
from harness.policy import PolicyEngine


def case(**kw: Any) -> GoldenCase:
    defaults: dict[str, Any] = dict(
        case_id="c1",
        label=Label.REACHABLE,
        repo="org/repo",
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        ecosystem="go",
        purl="pkg:golang/github.com/vuln/lib",
        manifest_path="go.mod",
    )
    defaults.update(kw)
    return GoldenCase(**defaults)


def outcome(label: Label, verdict: str, **kw: Any) -> Outcome:
    return Outcome(case_id=kw.pop("case_id", "c"), label=label, verdict=verdict, **kw)


class TestDataset:
    def test_roundtrip_from_dict(self) -> None:
        parsed = GoldenCase.from_dict(
            {
                "case_id": "c1",
                "label": "reachable",
                "repo": "org/repo",
                "ghsa_id": "GHSA-x",
                "ecosystem": "go",
                "purl": "pkg:golang/x",
            }
        )
        assert parsed.label is Label.REACHABLE

    def test_unknown_label_rejected(self) -> None:
        with pytest.raises(DatasetError, match="bad label"):
            GoldenCase.from_dict(
                {
                    "case_id": "c",
                    "label": "maybe",
                    "repo": "r",
                    "ghsa_id": "g",
                    "ecosystem": "go",
                    "purl": "p",
                }
            )

    def test_unknown_field_rejected(self) -> None:
        with pytest.raises(DatasetError, match="unknown fields"):
            GoldenCase.from_dict(
                {
                    "case_id": "c",
                    "label": "reachable",
                    "repo": "r",
                    "ghsa_id": "g",
                    "ecosystem": "go",
                    "purl": "p",
                    "typo": 1,
                }
            )

    def test_duplicate_case_id_rejected(self, tmp_path: Path) -> None:
        record = {
            "case_id": "dup",
            "label": "reachable",
            "repo": "r",
            "ghsa_id": "g",
            "ecosystem": "go",
            "purl": "p",
        }
        (tmp_path / "a.jsonl").write_text(json.dumps(record) + "\n" + json.dumps(record) + "\n")
        with pytest.raises(DatasetError, match="duplicate case_id"):
            load_golden(tmp_path)

    def test_missing_directory_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(DatasetError, match="not found"):
            load_golden(tmp_path / "nope")


class TestHoldoutSplit:
    def test_split_is_deterministic(self) -> None:
        first = case(case_id="stable-1").split
        second = case(case_id="stable-1").split
        assert first is second

    def test_split_depends_on_case_id_only(self) -> None:
        a = case(case_id="x", label=Label.REACHABLE, repo="org/a").split
        b = case(case_id="x", label=Label.NOT_REACHABLE, repo="org/b").split
        assert a is b

    def test_roughly_twenty_percent_held_out(self) -> None:
        cases = [case(case_id=f"c{i}") for i in range(1000)]
        held = sum(1 for c in cases if c.split is Split.HOLDOUT)
        assert 0.15 < held / len(cases) < 0.25

    def test_tune_and_holdout_partition_the_set(self) -> None:
        golden = GoldenSet([case(case_id=f"c{i}") for i in range(200)])
        assert len(golden.tune) + len(golden.holdout) == len(golden)
        assert not ({c.case_id for c in golden.tune} & {c.case_id for c in golden.holdout})


class TestMetrics:
    def test_false_negative_is_reachable_dismissed(self) -> None:
        assert outcome(Label.REACHABLE, "not_affected").is_false_negative
        assert outcome(Label.REACHABLE, "fixed").is_false_negative
        assert not outcome(Label.REACHABLE, "affected").is_false_negative

    def test_could_not_determine_is_not_a_false_negative(self) -> None:
        """Declining to answer is honest, not a dismissal."""
        assert not outcome(Label.REACHABLE, "could_not_determine").is_false_negative

    def test_unsure_label_excluded_from_scoring(self) -> None:
        report = EvalReport(outcomes=[outcome(Label.UNSURE, "not_affected")])
        assert report.decidable == []
        assert report.false_negative_rate == 0.0

    def test_rates_are_denominated_by_label_population(self) -> None:
        report = EvalReport(
            outcomes=[
                outcome(Label.REACHABLE, "not_affected"),
                outcome(Label.REACHABLE, "affected"),
                outcome(Label.REACHABLE, "affected"),
                outcome(Label.REACHABLE, "affected"),
                outcome(Label.NOT_REACHABLE, "affected"),
                outcome(Label.NOT_REACHABLE, "not_affected"),
            ]
        )
        assert report.false_negative_rate == 0.25
        assert report.false_positive_rate == 0.5

    def test_empty_report_does_not_divide_by_zero(self) -> None:
        report = EvalReport()
        assert report.false_negative_rate == 0.0
        assert report.precision == 0.0
        assert report.mean_cost_per_alert == 0.0

    def test_validator_disagreement_ignores_unjudged(self) -> None:
        report = EvalReport(
            outcomes=[
                outcome(Label.REACHABLE, "affected", validator_agreed=True),
                outcome(Label.REACHABLE, "affected", validator_agreed=False),
                outcome(Label.REACHABLE, "affected", validator_agreed=None),
            ]
        )
        assert report.validator_disagreement_rate == 0.5

    def test_false_negative_cases_are_named_in_the_report(self) -> None:
        report = EvalReport(outcomes=[outcome(Label.REACHABLE, "not_affected", case_id="leaked")])
        assert report.to_dict()["false_negative_cases"] == ["leaked"]


class TestGate:
    def test_cost_improvement_cannot_buy_a_worse_false_negative_rate(self) -> None:
        baseline = EvalReport(outcomes=[outcome(Label.REACHABLE, "affected", cost_usd=1.0)])
        candidate = EvalReport(outcomes=[outcome(Label.REACHABLE, "not_affected", cost_usd=0.01)])
        result = compare(baseline, candidate)
        assert result["accepted"] is False
        assert result["cost_delta_usd"] < 0
        assert "rejected" in result["reason"]

    def test_equal_false_negative_rate_is_accepted(self) -> None:
        baseline = EvalReport(outcomes=[outcome(Label.REACHABLE, "affected", cost_usd=1.0)])
        candidate = EvalReport(outcomes=[outcome(Label.REACHABLE, "affected", cost_usd=0.5)])
        assert compare(baseline, candidate)["accepted"] is True


@pytest.fixture()
def predictor() -> DeterministicPredictor:
    return DeterministicPredictor(PolicyEngine(load_policy("config/policy.yaml")))


class TestDeterministicPredictor:
    def test_policy_rule_decides(self, predictor: DeterministicPredictor) -> None:
        prediction = predictor.predict(case(resolved_version="2.0.0", patched_version="1.0.0"))
        assert prediction.verdict == "fixed"
        assert prediction.decided_by == "policy"
        assert prediction.rule_id == "already_fixed"

    def test_reachable_evidence_yields_affected(self, predictor: DeterministicPredictor) -> None:
        prediction = predictor.predict(
            case(
                resolved_version="1.0.0",
                patched_version="9.0.0",
                reachability_level=4,
                reachability_confidence=0.9,
                reachability_method="govulncheck",
                symbols=["x.Y"],
            )
        )
        assert prediction.verdict == "affected"
        assert prediction.decided_by == "evidence"

    def test_toolchain_failure_is_could_not_determine(
        self, predictor: DeterministicPredictor
    ) -> None:
        prediction = predictor.predict(
            case(
                resolved_version="1.0.0",
                patched_version="9.0.0",
                reachability_method="failed",
                dep_scope="unknown",
            )
        )
        assert prediction.verdict == "could_not_determine"

    def test_mid_scale_evidence_is_could_not_determine(
        self, predictor: DeterministicPredictor
    ) -> None:
        prediction = predictor.predict(
            case(
                resolved_version="1.0.0",
                patched_version="9.0.0",
                reachability_level=3,
                reachability_method="govulncheck",
            )
        )
        assert prediction.verdict == "could_not_determine"

    def test_deterministic_pipeline_costs_nothing(self, predictor: DeterministicPredictor) -> None:
        prediction = predictor.predict(case(resolved_version="2.0.0", patched_version="1.0.0"))
        assert prediction.cost_usd == 0.0


class TestSeedSetBaseline:
    def test_seed_set_exists_and_is_large_enough(self) -> None:
        golden = load_golden("eval/golden")
        assert len(golden) >= 100

    def test_baseline_has_no_false_negatives(self, predictor: DeterministicPredictor) -> None:
        """The deterministic pipeline must never dismiss a reachable vulnerability."""
        golden = load_golden("eval/golden")
        report = evaluate(golden.tune, predictor)
        assert report.false_negatives == []
        assert report.false_negative_rate == 0.0

    def test_holdout_is_not_scored_by_default(self, predictor: DeterministicPredictor) -> None:
        golden = load_golden("eval/golden")
        report = evaluate(golden.tune, predictor)
        holdout_ids = {c.case_id for c in golden.holdout}
        assert not ({o.case_id for o in report.outcomes} & holdout_ids)

    def test_every_case_receives_a_verdict(self, predictor: DeterministicPredictor) -> None:
        golden = load_golden("eval/golden")
        report = evaluate(golden, predictor)
        assert len(report.outcomes) == len(golden)
        assert all(o.verdict for o in report.outcomes)


class TestPredictorProtocol:
    def test_alternative_predictor_scores_through_the_same_path(self) -> None:
        class AlwaysAffected:
            name = "stub"

            def predict(self, case: GoldenCase) -> Prediction:
                return Prediction(verdict="affected", cost_usd=0.25)

        golden = GoldenSet([case(case_id="a", label=Label.NOT_REACHABLE)])
        report = evaluate(golden, AlwaysAffected())
        assert report.false_positive_rate == 1.0
        assert report.mean_cost_per_alert == 0.25


class TestAntiGaming:
    def test_abstaining_everywhere_is_measured_even_though_it_is_not_a_false_negative(
        self,
    ) -> None:
        report = EvalReport(
            outcomes=[
                outcome(Label.REACHABLE, "could_not_determine"),
                outcome(Label.REACHABLE, "could_not_determine"),
                outcome(Label.NOT_REACHABLE, "could_not_determine"),
            ]
        )
        assert report.false_negative_rate == 0.0
        assert report.abstention_on_reachable_rate == 1.0
        assert report.could_not_determine_rate == 1.0

    def test_gate_rejects_a_pipeline_that_abstains_its_way_to_zero(self) -> None:
        baseline = EvalReport(
            outcomes=[
                outcome(Label.REACHABLE, "affected", case_id="a"),
                outcome(Label.REACHABLE, "not_affected", case_id="b"),
            ]
        )
        candidate = EvalReport(
            outcomes=[
                outcome(Label.REACHABLE, "could_not_determine", case_id="a"),
                outcome(Label.REACHABLE, "could_not_determine", case_id="b"),
            ]
        )
        result = compare(baseline, candidate)
        assert result["false_negative_rate_delta"] < 0
        assert result["accepted"] is False
        assert "abstention" in result["reason"]

    def test_could_not_determine_rate_is_not_diluted_by_unsure_cases(self) -> None:
        outcomes = [outcome(Label.UNSURE, "affected", case_id=f"u{i}") for i in range(90)]
        outcomes += [
            outcome(Label.REACHABLE, "could_not_determine", case_id=f"d{i}") for i in range(10)
        ]
        report = EvalReport(outcomes=outcomes)
        assert report.could_not_determine_rate == 1.0


class TestDatasetComparability:
    def test_gate_refuses_to_compare_different_case_sets(self) -> None:
        baseline = EvalReport(outcomes=[outcome(Label.REACHABLE, "affected", case_id="a")])
        candidate = EvalReport(
            outcomes=[
                outcome(Label.REACHABLE, "affected", case_id="a"),
                outcome(Label.REACHABLE, "affected", case_id="b"),
            ]
        )
        result = compare(baseline, candidate)
        assert result["comparable"] is False
        assert result["accepted"] is False

    def test_fingerprint_ignores_outcome_order(self) -> None:
        first = EvalReport(
            outcomes=[
                outcome(Label.REACHABLE, "affected", case_id="a"),
                outcome(Label.REACHABLE, "affected", case_id="b"),
            ]
        )
        second = EvalReport(
            outcomes=[
                outcome(Label.REACHABLE, "affected", case_id="b"),
                outcome(Label.REACHABLE, "affected", case_id="a"),
            ]
        )
        assert first.dataset_fingerprint == second.dataset_fingerprint


class TestEvidenceTrust:
    def test_level_zero_without_confidence_is_not_a_clearance(
        self, predictor: DeterministicPredictor
    ) -> None:
        """An unset level must not read as 'absent from the resolved tree'."""
        prediction = predictor.predict(
            case(
                resolved_version="1.0.0",
                patched_version="9.0.0",
                reachability_level=0,
                reachability_method="govulncheck",
                reachability_confidence=0.0,
            )
        )
        assert prediction.verdict == "could_not_determine"
        assert prediction.decided_by == "unresolved"

    def test_level_zero_with_real_confidence_is_a_clearance(
        self, predictor: DeterministicPredictor
    ) -> None:
        prediction = predictor.predict(
            case(
                resolved_version="1.0.0",
                patched_version="9.0.0",
                reachability_level=0,
                reachability_method="govulncheck",
                reachability_confidence=0.9,
            )
        )
        assert prediction.verdict == "not_affected"

    def test_missing_method_is_not_a_measurement(self, predictor: DeterministicPredictor) -> None:
        prediction = predictor.predict(
            case(
                resolved_version="1.0.0",
                patched_version="9.0.0",
                reachability_level=1,
                reachability_confidence=0.9,
            )
        )
        assert prediction.verdict == "could_not_determine"
