from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from harness.config import HarnessConfig, load_config
from harness.db import AlertRecord, Database
from harness.emit import comment, openvex, sarif
from harness.emit.dismissal import DismissalGate, dismissal_comment
from harness.sources.github import GithubError
from harness.stages.emit import EmitStage
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
output:
  vex_dir: ./out/vex
  sarif_dir: ./out/sarif
  auto_dismiss: true
  auto_dismiss_requires:
    verdict: not_affected
    confidence_min: 0.85
    validator_agreed: true
"""

NOT_AFFECTED = {
    "alert_key": "k1",
    "verdict": "not_affected",
    "vex_status": "not_affected",
    "vex_justification": "vulnerable_code_not_in_execute_path",
    "confidence": 0.9,
    "needs_human": False,
    "severity_rationale": "symbol never called",
    "recommended_action": "no action",
    "evidence_cited": [{"file": "a.go", "line": 3, "why": "no call path"}],
    "unknowns": [],
}

AFFECTED = {
    **NOT_AFFECTED,
    "verdict": "affected",
    "vex_status": "affected",
    "vex_justification": None,
    "recommended_action": "bump vuln-lib to 0.3.4",
}

UNDETERMINED = {
    **NOT_AFFECTED,
    "verdict": "could_not_determine",
    "vex_status": "under_investigation",
    "vex_justification": None,
    "confidence": 0.0,
    "needs_human": True,
}


class FakeGithub:
    def __init__(self, *, fail: bool = False) -> None:
        self.dismissals: list[tuple[str, int, str, str]] = []
        self.fail = fail

    def dismiss_alert(self, repo: str, number: int, *, reason: str, comment: str) -> None:
        if self.fail:
            raise GithubError("403 forbidden")
        self.dismissals.append((repo, number, reason, comment))


@pytest.fixture()
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessConfig:
    monkeypatch.setenv("GH_TOKEN", "ghp_test")
    path = tmp_path / "harness.yaml"
    path.write_text(CONFIG)
    loaded = load_config(path)
    object.__setattr__(loaded.storage, "db_path", tmp_path / "harness.db")
    object.__setattr__(loaded.output, "vex_dir", tmp_path / "vex")
    object.__setattr__(loaded.output, "sarif_dir", tmp_path / "sarif")
    return loaded


def seed(
    db: Database,
    verdict: dict[str, Any],
    *,
    validated: bool | None = True,
    alert_key: str = "k1",
    run_id: str = "run1",
    **kw: Any,
) -> AlertRecord:
    defaults: dict[str, Any] = dict(
        alert_key=alert_key,
        repo="my-org/service-a",
        ghsa_id="GHSA-x",
        purl="pkg:golang/github.com/vuln/lib",
        ecosystem="go",
        manifest_path="go.mod",
        gh_alert_num=7,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        state="open",
        cvss_score=7.5,
    )
    defaults.update(kw)
    record = AlertRecord(**defaults)
    db.upsert_alert(record)
    db.record_stage(
        run_id=run_id,
        alert_key=alert_key,
        stage="evidence",
        status="done",
        payload={
            "reachability": {"level": 2, "confidence": 0.9, "method": "govulncheck"},
            "advisory": {"summary": "a parsing flaw"},
        },
    )
    db.put_verdict(
        alert_key=alert_key,
        run_id=run_id,
        verdict={**verdict, "alert_key": alert_key},
        validated=validated,
        structure_hash="h1",
    )
    return record


class TestOpenVex:
    def test_document_shape(self) -> None:
        statement = openvex.statement_from_verdict(
            {**NOT_AFFECTED, "ghsa_id": "GHSA-x"}, "pkg:golang/x"
        )
        document = openvex.build_document("my-org/service-a", [statement])
        assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert document["statements"][0]["status"] == "not_affected"
        assert document["statements"][0]["products"][0]["@id"] == "pkg:golang/x"

    def test_not_affected_always_carries_a_justification(self) -> None:
        statement = openvex.statement_from_verdict(
            {**NOT_AFFECTED, "ghsa_id": "GHSA-x"}, "pkg:golang/x"
        )
        assert statement.justification == "vulnerable_code_not_in_execute_path"

    def test_not_affected_without_a_justification_is_not_emitted(self) -> None:
        """A consumer cannot suppress a finding it has no justification for."""
        payload = {**NOT_AFFECTED, "vex_justification": None, "ghsa_id": "GHSA-x"}
        assert openvex.statement_from_verdict(payload, "pkg:golang/x") is None

    def test_could_not_determine_maps_to_under_investigation(self) -> None:
        statement = openvex.statement_from_verdict(
            {**UNDETERMINED, "ghsa_id": "GHSA-x"}, "pkg:golang/x"
        )
        assert statement.status == "under_investigation"

    def test_affected_carries_the_action(self) -> None:
        statement = openvex.statement_from_verdict({**AFFECTED, "ghsa_id": "GHSA-x"}, "pkg:x")
        assert statement.action_statement == "bump vuln-lib to 0.3.4"

    def test_document_id_is_stable_for_the_same_content(self) -> None:
        statement = openvex.statement_from_verdict({**AFFECTED, "ghsa_id": "GHSA-x"}, "pkg:x")
        first = openvex.build_document("r", [statement], timestamp="2026-01-01T00:00:00+00:00")
        second = openvex.build_document("r", [statement], timestamp="2026-01-01T00:00:00+00:00")
        assert first["@id"] == second["@id"]


class TestSarif:
    def test_property_bag_carries_the_analysis(self) -> None:
        report = sarif.build_report(
            "my-org/service-a",
            [
                {
                    "ghsa_id": "GHSA-x",
                    "verdict": "affected",
                    "reachability_level": 4,
                    "reachability_confidence": 0.9,
                    "analysis_method": "govulncheck",
                    "validator_agreed": True,
                    "evidence_cited": [{"file": "a.go", "line": 12}],
                }
            ],
        )
        properties = report["runs"][0]["results"][0]["properties"]
        assert properties["reachability_level"] == 4
        assert properties["reachability_confidence"] == 0.9
        assert properties["analysis_method"] == "govulncheck"
        assert properties["validator_agreed"] is True

    def test_verdict_maps_to_sarif_level(self) -> None:
        findings = [
            {"ghsa_id": "a", "verdict": "affected"},
            {"ghsa_id": "b", "verdict": "not_affected"},
            {"ghsa_id": "c", "verdict": "could_not_determine"},
        ]
        levels = [r["level"] for r in sarif.build_report("r", findings)["runs"][0]["results"]]
        assert levels == ["error", "none", "warning"]

    def test_schema_and_version_are_declared(self) -> None:
        report = sarif.build_report("r", [{"ghsa_id": "a", "verdict": "affected"}])
        assert report["version"] == "2.1.0"
        assert "sarif-2.1.0" in report["$schema"]

    def test_unverified_validator_is_null_not_false(self) -> None:
        report = sarif.build_report(
            "r", [{"ghsa_id": "a", "verdict": "affected", "validator_agreed": None}]
        )
        assert report["runs"][0]["results"][0]["properties"]["validator_agreed"] is None


class TestDismissalGate:
    def gate(self, **overrides: Any) -> DismissalGate:
        requirements = {
            "verdict": "not_affected",
            "confidence_min": 0.85,
            "validator_agreed": True,
        }
        requirements.update(overrides)
        return DismissalGate(enabled=True, requirements=requirements)

    def test_fully_satisfied_gate_allows(self) -> None:
        assert self.gate().evaluate(NOT_AFFECTED, True).allowed

    def test_wrong_verdict_blocks(self) -> None:
        decision = self.gate().evaluate(AFFECTED, True)
        assert not decision.allowed
        assert "verdict is" in decision.blocked_by

    def test_low_confidence_blocks(self) -> None:
        decision = self.gate().evaluate({**NOT_AFFECTED, "confidence": 0.5}, True)
        assert not decision.allowed
        assert "confidence" in decision.blocked_by

    def test_disputed_validator_blocks(self) -> None:
        assert not self.gate().evaluate(NOT_AFFECTED, False).allowed

    def test_unconfirmed_validator_blocks(self) -> None:
        """An unchecked verdict is not a confirmed verdict; None must never pass."""
        decision = self.gate().evaluate(NOT_AFFECTED, None)
        assert not decision.allowed
        assert "unconfirmed" in decision.blocked_by

    def test_needs_human_blocks(self) -> None:
        assert not self.gate().evaluate({**NOT_AFFECTED, "needs_human": True}, True).allowed

    def test_missing_justification_blocks(self) -> None:
        payload = {**NOT_AFFECTED, "vex_justification": None}
        assert not self.gate().evaluate(payload, True).allowed

    def test_disabled_gate_blocks_everything(self) -> None:
        gate = DismissalGate(enabled=False, requirements={})
        assert not gate.evaluate(NOT_AFFECTED, True).allowed

    def test_every_blocker_is_reported(self) -> None:
        payload = {**NOT_AFFECTED, "confidence": 0.1, "needs_human": True}
        decision = self.gate().evaluate(payload, None)
        assert len(decision.reasons) >= 3

    def test_comment_carries_code_and_evidence(self) -> None:
        body = dismissal_comment(NOT_AFFECTED)
        assert "vulnerable_code_not_in_execute_path" in body
        assert "a.go:3" in body


class TestPrCommentDiff:
    def test_only_changes_are_rendered(self) -> None:
        base = {"k1": {**AFFECTED, "purl": "pkg:x", "ghsa_id": "GHSA-1"}}
        head = {
            "k1": {**AFFECTED, "purl": "pkg:x", "ghsa_id": "GHSA-1"},
            "k2": {**AFFECTED, "purl": "pkg:y", "ghsa_id": "GHSA-2"},
        }
        body = comment.render(comment.diff_verdicts(base, head), repo="r")
        assert "pkg:y" in body
        assert "pkg:x" not in body

    def test_changed_verdict_shows_the_previous_state(self) -> None:
        base = {"k1": {**NOT_AFFECTED, "purl": "pkg:x"}}
        head = {"k1": {**AFFECTED, "purl": "pkg:x"}}
        body = comment.render(comment.diff_verdicts(base, head), repo="r")
        assert "was: not affected" in body

    def test_no_changes_says_so_briefly(self) -> None:
        base = {"k1": {**AFFECTED, "purl": "pkg:x"}}
        body = comment.render(comment.diff_verdicts(base, base), repo="r")
        assert "no verdict changes" in body
        assert len(body.splitlines()) == 1

    def test_reachable_findings_sort_first(self) -> None:
        head = {
            "k1": {**NOT_AFFECTED, "purl": "pkg:a"},
            "k2": {**AFFECTED, "purl": "pkg:b"},
        }
        body = comment.render(comment.diff_verdicts({}, head), repo="r")
        assert body.index("pkg:b") < body.index("pkg:a")


class TestEmitStage:
    def test_writes_vex_and_sarif(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, AFFECTED)
            report = EmitStage(cfg, db, github=FakeGithub()).run("run1")

            result = report.repos[0]
            assert Path(result.vex_path).is_file()
            assert Path(result.sarif_path).is_file()
            vex = json.loads(Path(result.vex_path).read_text())
            assert vex["statements"][0]["status"] == "affected"

    def test_gated_dismissal_is_performed(self, cfg: HarnessConfig) -> None:
        github = FakeGithub()
        with Database(cfg.storage.db_path) as db:
            seed(db, NOT_AFFECTED, validated=True)
            report = EmitStage(cfg, db, github=github).run("run1")

            assert report.dismissed == 1
            _repo, number, reason, body = github.dismissals[0]
            assert number == 7
            assert reason == "tolerable_risk"
            assert "vulnerable_code_not_in_execute_path" in body

    def test_unconfirmed_verdict_is_never_dismissed(self, cfg: HarnessConfig) -> None:
        github = FakeGithub()
        with Database(cfg.storage.db_path) as db:
            seed(db, NOT_AFFECTED, validated=None)
            report = EmitStage(cfg, db, github=github).run("run1")

            assert report.dismissed == 0
            assert github.dismissals == []
            assert report.repos[0].dismissal_blocked == 1

    def test_affected_is_never_dismissed(self, cfg: HarnessConfig) -> None:
        github = FakeGithub()
        with Database(cfg.storage.db_path) as db:
            seed(db, AFFECTED, validated=True)
            EmitStage(cfg, db, github=github).run("run1")
            assert github.dismissals == []

    def test_dismissal_failure_is_reported_not_swallowed(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, NOT_AFFECTED, validated=True)
            report = EmitStage(cfg, db, github=FakeGithub(fail=True)).run("run1")

            assert report.dismissed == 0
            assert any("dismissal failed" in e for e in report.repos[0].errors)

    def test_no_verdicts_writes_nothing(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            report = EmitStage(cfg, db, github=FakeGithub()).run("run1")
            assert report.repos[0].vex_path is None

    def test_pr_comment_diffs_against_a_base_run(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, NOT_AFFECTED, alert_key="k1", run_id="base")
            seed(db, AFFECTED, alert_key="k1", run_id="run1")
            body = EmitStage(cfg, db).render_pr_comment("run1", "my-org/service-a", "base")
            assert "was: not affected" in body

    def test_pr_comment_without_a_base_lists_everything_once(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, AFFECTED)
            body = EmitStage(cfg, db).render_pr_comment("run1", "my-org/service-a", None)
            assert "New (1)" in body


class TestGrypeConsumesTheEmittedVex:
    """The M8 accept gate, recorded from a real `grype` run.

    A vulnerable module (golang.org/x/text v0.3.0) produced four findings. Feeding grype
    an OpenVEX document built by `harness.emit.openvex` marking one of them
    `not_affected` suppressed exactly that finding and left the other three reported.
    """

    FIXTURES = Path(__file__).parent / "fixtures"

    def test_baseline_scan_reported_four_findings(self) -> None:
        report = json.loads((self.FIXTURES / "grype_base.json").read_text())
        assert len(report["matches"]) == 4

    def test_vex_suppressed_exactly_the_stated_finding(self) -> None:
        report = json.loads((self.FIXTURES / "grype_versioned.json").read_text())
        ignored = report.get("ignoredMatches") or []

        assert len(ignored) == 1
        assert ignored[0]["vulnerability"]["id"] == "GHSA-5rcv-m4m3-hfh7"
        assert ignored[0]["appliedIgnoreRules"][0]["vex-status"] == "not_affected"

    def test_unstated_findings_are_still_reported(self) -> None:
        report = json.loads((self.FIXTURES / "grype_versioned.json").read_text())
        still_reported = {m["vulnerability"]["id"] for m in report["matches"]}
        assert still_reported == {
            "GHSA-69ch-w2m2-3vjp",
            "GHSA-ppp9-7jff-5vj2",
            "GO-2026-5970",
        }

    def test_the_document_that_did_it_is_what_our_emitter_produces(self) -> None:
        statement = openvex.statement_from_verdict(
            {
                "verdict": "not_affected",
                "vex_status": "not_affected",
                "vex_justification": "vulnerable_code_not_in_execute_path",
                "ghsa_id": "GHSA-5rcv-m4m3-hfh7",
            },
            "pkg:golang/golang.org/x/text@v0.3.0",
        )
        document = openvex.build_document("my-org/probe", [statement])

        assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
        entry = document["statements"][0]
        assert entry["vulnerability"]["name"] == "GHSA-5rcv-m4m3-hfh7"
        assert entry["products"][0]["@id"] == "pkg:golang/golang.org/x/text@v0.3.0"
        assert entry["status"] == "not_affected"
        assert entry["justification"] == "vulnerable_code_not_in_execute_path"


class TestGateFailsClosed:
    def test_enabled_with_no_requirements_dismisses_nothing(self) -> None:
        """An omitted requirements block is an unstated bar, not an empty one."""
        gate = DismissalGate(enabled=True, requirements={})
        decision = gate.evaluate(NOT_AFFECTED, True)
        assert not decision.allowed
        assert "unstated bar" in decision.blocked_by

    @pytest.mark.parametrize("omitted", ["verdict", "confidence_min", "validator_agreed"])
    def test_any_missing_requirement_blocks(self, omitted: str) -> None:
        requirements = {
            "verdict": "not_affected",
            "confidence_min": 0.85,
            "validator_agreed": True,
        }
        del requirements[omitted]
        decision = DismissalGate(enabled=True, requirements=requirements).evaluate(
            NOT_AFFECTED, True
        )
        assert not decision.allowed
        assert omitted in decision.blocked_by

    def test_verdict_document_without_a_verdict_field_blocks(self) -> None:
        gate = DismissalGate(
            enabled=True,
            requirements={
                "verdict": "not_affected",
                "confidence_min": 0.85,
                "validator_agreed": True,
            },
        )
        payload = {k: v for k, v in NOT_AFFECTED.items() if k != "verdict"}
        assert not gate.evaluate(payload, True).allowed


class TestOpenVexRequiresAnIdentifier:
    def test_statement_without_a_vulnerability_id_is_not_emitted(self) -> None:
        payload = {**NOT_AFFECTED}
        payload.pop("ghsa_id", None)
        assert openvex.statement_from_verdict(payload, "pkg:golang/x") is None


class TestDismissalIdempotency:
    def test_a_second_run_does_not_re_dismiss(self, cfg: HarnessConfig) -> None:
        github = FakeGithub()
        with Database(cfg.storage.db_path) as db:
            seed(db, NOT_AFFECTED, validated=True, run_id="run1")
            EmitStage(cfg, db, github=github).run("run1")
            assert len(github.dismissals) == 1

            db.put_verdict(
                alert_key="k1",
                run_id="run2",
                verdict={**NOT_AFFECTED, "alert_key": "k1"},
                validated=True,
                structure_hash="h1",
            )
            EmitStage(cfg, db, github=github).run("run2")
            assert len(github.dismissals) == 1

    def test_a_failed_dismissal_is_recorded_and_retried(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, NOT_AFFECTED, validated=True)
            EmitStage(cfg, db, github=FakeGithub(fail=True)).run("run1")
            assert db.stage_status("run1", "k1", "emit") == "failed"

            github = FakeGithub()
            db.put_verdict(
                alert_key="k1",
                run_id="run2",
                verdict={**NOT_AFFECTED, "alert_key": "k1"},
                validated=True,
                structure_hash="h1",
            )
            EmitStage(cfg, db, github=github).run("run2")
            assert len(github.dismissals) == 1

    def test_missing_github_client_is_recorded_not_silent(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, NOT_AFFECTED, validated=True)
            report = EmitStage(cfg, db, github=None).run("run1")
            assert db.stage_status("run1", "k1", "emit") == "failed"
            assert any("no GitHub client" in e for e in report.repos[0].errors)


class TestCommentConfidenceFormatting:
    def test_boolean_confidence_is_not_rendered_as_a_percentage(self) -> None:
        head = {"k1": {**AFFECTED, "purl": "pkg:x", "confidence": True}}
        body = comment.render(comment.diff_verdicts({}, head), repo="r")
        assert "100% confidence" not in body


class TestIncompleteCoverageBlocksDismissal:
    """A partial scan does not know what it missed, so it dismisses nothing."""

    def gate(self, *, complete: bool) -> DismissalGate:
        return DismissalGate(
            enabled=True,
            requirements={
                "verdict": "not_affected",
                "confidence_min": 0.85,
                "validator_agreed": True,
            },
            coverage_complete=complete,
        )

    def test_complete_coverage_allows_an_otherwise_valid_dismissal(self) -> None:
        assert self.gate(complete=True).evaluate(NOT_AFFECTED, True).allowed

    def test_incomplete_coverage_blocks_it(self) -> None:
        decision = self.gate(complete=False).evaluate(NOT_AFFECTED, True)
        assert not decision.allowed
        assert "coverage" in decision.blocked_by

    def test_the_stage_honours_the_flag(self, cfg: HarnessConfig) -> None:
        github = FakeGithub()
        with Database(cfg.storage.db_path) as db:
            seed(db, NOT_AFFECTED, validated=True)
            report = EmitStage(cfg, db, github=github, coverage_complete=False).run("run1")
            assert report.dismissed == 0
            assert github.dismissals == []
