from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from harness.config import HarnessConfig, load_config
from harness.db import AlertRecord, Database
from harness.models import BudgetLedger, ModelClient, ModelRequest, ModelResponse, Usage
from harness.schemas import SchemaViolation, validate
from harness.sources.checkout import Checkout, CheckoutError
from harness.stages.validate import ValidationStage
from harness.util import utcnow
from harness.validation.mechanical import check_verdict

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

VERDICT = {
    "alert_key": "k1",
    "threat_model": {
        "attacker": "unauthenticated internet client",
        "boundary_crossed": "edge -> api",
        "assumption_broken": "parser assumes well-formed input",
        "preconditions": [],
    },
    "verdict": "affected",
    "vex_status": "affected",
    "vex_justification": None,
    "reachability_confirmed": True,
    "confidence": 0.8,
    "production_reachable": True,
    "severity_adjusted": "high",
    "severity_rationale": "upheld",
    "evidence_cited": [{"file": "parse.go", "line": 2, "why": "reached from handler"}],
    "recommended_action": "bump",
    "owner_hint": None,
    "unknowns": [],
    "needs_human": False,
}

BUNDLE_REACHABLE = {
    "alert_key": "k1",
    "reachability": {"level": 4, "scale": {}, "confidence": 0.9, "method": "govulncheck"},
    "advisory": {"ghsa_id": "GHSA-x", "summary": "", "affected_symbols": []},
    "exploitability": {},
    "truncated": False,
}

AGREES = {"agrees": True, "strongest_objection": "", "cited_counter_evidence": []}
DISPUTES = {
    "agrees": False,
    "strongest_objection": "the cited call site is in a build-tagged test helper",
    "cited_counter_evidence": [{"file": "parse.go", "line": 1, "why": "//go:build testing"}],
}


class FakeProvider:
    def __init__(self, text: str) -> None:
        self.text = text
        self.calls = 0

    def complete(self, request: ModelRequest, model: str) -> ModelResponse:
        self.calls += 1
        return ModelResponse(text=self.text, usage=Usage(tokens_in=2000, tokens_out=300))


class FakeCheckouts:
    def __init__(self, root: Path | None) -> None:
        self.root = root

    def ensure(self, repo: str, commit_sha: str) -> Checkout:
        if self.root is None:
            raise CheckoutError("unavailable")
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
    root.mkdir()
    (root / "parse.go").write_text("package p\nfunc Parse() {}\nfunc Other() {}\n")
    return root


def seed(db: Database, verdict: dict[str, Any] | None = None, **kw: Any) -> AlertRecord:
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
    )
    defaults.update(kw)
    record = AlertRecord(**defaults)
    db.upsert_alert(record)
    db.record_snapshot("my-org/service-a", "sha1", "h1")
    db.record_stage(
        run_id="run1",
        alert_key=record.alert_key,
        stage="evidence",
        status="done",
        payload=BUNDLE_REACHABLE,
    )
    db.record_stage(run_id="run1", alert_key=record.alert_key, stage="judgment", status="done")
    db.put_verdict(
        alert_key=record.alert_key,
        run_id="run1",
        verdict=verdict or VERDICT,
        structure_hash="h1",
    )
    return record


def build(
    cfg: HarnessConfig, db: Database, provider: FakeProvider, root: Path | None
) -> ValidationStage:
    ledger = BudgetLedger(cfg.budgets, db, "run1")
    client = ModelClient(cfg.model("validator"), ledger, provider=provider)
    return ValidationStage(cfg, db, ledger, client=client, checkouts=FakeCheckouts(root))


class TestValidatorCannotFileFindings:
    """The constraint is structural, in the schema, not an instruction in the prompt."""

    def test_agreement_and_objection_are_the_only_shapes(self) -> None:
        validate("validator_response", AGREES)
        validate("validator_response", DISPUTES)

    def test_a_verdict_field_is_rejected(self) -> None:
        payload = dict(AGREES)
        payload["verdict"] = "affected"
        with pytest.raises(SchemaViolation):
            validate("validator_response", payload)

    def test_a_severity_field_is_rejected(self) -> None:
        payload = dict(AGREES)
        payload["severity"] = "critical"
        with pytest.raises(SchemaViolation):
            validate("validator_response", payload)

    def test_any_extra_field_is_rejected(self) -> None:
        payload = dict(AGREES)
        payload["my_own_finding"] = "I found something else"
        with pytest.raises(SchemaViolation):
            validate("validator_response", payload)

    def test_counter_evidence_must_be_cited_with_file_and_line(self) -> None:
        payload = dict(DISPUTES)
        payload["cited_counter_evidence"] = [{"why": "trust me"}]
        with pytest.raises(SchemaViolation):
            validate("validator_response", payload)


class TestMechanicalChecks:
    def test_valid_verdict_passes_everything(self, source: Path) -> None:
        report = check_verdict(VERDICT, bundle=BUNDLE_REACHABLE, repo_root=source, ecosystem="go")
        assert report.passed

    def test_nonexistent_cited_file_is_rejected(self, source: Path) -> None:
        payload = dict(VERDICT)
        payload["evidence_cited"] = [{"file": "ghost.go", "line": 1, "why": "x"}]
        report = check_verdict(payload, repo_root=source, ecosystem="go")
        assert not report.passed
        assert any("does not exist" in f.detail for f in report.failures)

    def test_out_of_range_cited_line_is_rejected(self, source: Path) -> None:
        payload = dict(VERDICT)
        payload["evidence_cited"] = [{"file": "parse.go", "line": 9999, "why": "x"}]
        report = check_verdict(payload, repo_root=source, ecosystem="go")
        assert not report.passed
        assert any("outside" in f.detail for f in report.failures)

    def test_citation_escaping_the_checkout_is_rejected(self, source: Path) -> None:
        payload = dict(VERDICT)
        payload["evidence_cited"] = [{"file": "../../etc/passwd", "line": 1, "why": "x"}]
        report = check_verdict(payload, repo_root=source, ecosystem="go")
        assert not report.passed

    def test_confidence_above_the_ecosystem_ceiling_is_rejected(self) -> None:
        payload = dict(VERDICT)
        payload["confidence"] = 0.99
        report = check_verdict(payload, ecosystem="npm")
        assert not report.passed
        assert any("ceiling" in f.detail for f in report.failures)

    def test_npm_cannot_produce_a_high_confidence_dismissal(self) -> None:
        payload = dict(VERDICT)
        payload["verdict"] = "not_affected"
        payload["vex_status"] = "not_affected"
        payload["vex_justification"] = "vulnerable_code_not_in_execute_path"
        payload["confidence"] = 0.8
        report = check_verdict(payload, ecosystem="npm")
        assert not report.passed

    def test_not_affected_at_proven_reachability_is_a_contradiction(self) -> None:
        payload = dict(VERDICT)
        payload["verdict"] = "not_affected"
        payload["vex_status"] = "not_affected"
        payload["vex_justification"] = "vulnerable_code_not_in_execute_path"
        payload["confidence"] = 0.5
        report = check_verdict(payload, bundle=BUNDLE_REACHABLE, ecosystem="go")
        assert not report.passed
        assert any("contradicts reachability" in f.detail for f in report.failures)

    def test_failed_toolchain_is_not_a_contradiction(self, source: Path) -> None:
        payload = dict(VERDICT)
        payload["verdict"] = "not_affected"
        payload["vex_status"] = "not_affected"
        payload["vex_justification"] = "vulnerable_code_not_in_execute_path"
        payload["confidence"] = 0.4
        bundle = {"reachability": {"level": 0, "scale": {}, "confidence": 0.0, "method": "failed"}}
        report = check_verdict(payload, bundle=bundle, repo_root=source, ecosystem="go")
        assert report.passed

    def test_missing_justification_is_rejected(self) -> None:
        payload = dict(VERDICT)
        payload["vex_status"] = "not_affected"
        payload["vex_justification"] = None
        report = check_verdict(payload, ecosystem="go")
        assert not report.passed

    def test_all_failures_are_reported_at_once(self, source: Path) -> None:
        payload = dict(VERDICT)
        payload["confidence"] = 0.99
        payload["evidence_cited"] = [{"file": "ghost.go", "line": 1, "why": "x"}]
        report = check_verdict(payload, repo_root=source, ecosystem="npm")
        assert len(report.failures) >= 2


class TestValidationStage:
    def test_agreement_marks_the_verdict_validated(self, cfg: HarnessConfig, source: Path) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            report = build(cfg, db, FakeProvider(json.dumps(AGREES)), source).run("run1")

            assert report.agreed == 1
            assert db.latest_verdict("k1")["validated"] == 1

    def test_dispute_goes_to_the_human_queue(self, cfg: HarnessConfig, source: Path) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            report = build(cfg, db, FakeProvider(json.dumps(DISPUTES)), source).run("run1")

            assert report.disputed == 1
            assert "k1" in report.human_queue
            assert db.latest_verdict("k1")["validated"] == 0
            assert "build-tagged" in db.latest_verdict("k1")["validator_notes"]

    def test_dispute_is_never_resolved_by_a_third_model(
        self, cfg: HarnessConfig, source: Path
    ) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            provider = FakeProvider(json.dumps(DISPUTES))
            build(cfg, db, provider, source).run("run1")
            assert provider.calls == 1

    def test_mechanical_failure_skips_the_agent_entirely(
        self, cfg: HarnessConfig, source: Path
    ) -> None:
        bad = dict(VERDICT)
        bad["evidence_cited"] = [{"file": "ghost.go", "line": 1, "why": "x"}]
        with Database(cfg.storage.db_path) as db:
            seed(db, verdict=bad)
            provider = FakeProvider(json.dumps(AGREES))
            report = build(cfg, db, provider, source).run("run1")

            assert report.mechanically_rejected == 1
            assert provider.calls == 0
            assert db.latest_verdict("k1")["validated"] == 0

    def test_validator_unavailable_leaves_the_verdict_unconfirmed(
        self, cfg: HarnessConfig, source: Path
    ) -> None:
        """Unconfirmed is distinct from disputed and from agreed."""
        with Database(cfg.storage.db_path) as db:
            seed(db)
            provider = FakeProvider("Internal Server Error")
            report = build(cfg, db, provider, source).run("run1")

            assert report.validator_unavailable == 1
            assert db.latest_verdict("k1")["validated"] is None
            assert "k1" in report.human_queue

    def test_validator_response_with_extra_fields_is_discarded(
        self, cfg: HarnessConfig, source: Path
    ) -> None:
        rogue = dict(AGREES)
        rogue["verdict"] = "not_affected"
        with Database(cfg.storage.db_path) as db:
            seed(db)
            report = build(cfg, db, FakeProvider(json.dumps(rogue)), source).run("run1")

            assert report.validator_unavailable == 1
            assert db.latest_verdict("k1")["validated"] is None

    def test_disagreement_rate_is_reported(self, cfg: HarnessConfig, source: Path) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db, alert_key="k1")
            seed(db, alert_key="k2")
            report = build(cfg, db, FakeProvider(json.dumps(DISPUTES)), source).run("run1")
            assert report.disagreement_rate == 1.0

    def test_unjudged_alerts_are_not_validated(self, cfg: HarnessConfig, source: Path) -> None:
        with Database(cfg.storage.db_path) as db:
            record = seed(db)
            db.record_stage(
                run_id="run1", alert_key=record.alert_key, stage="judgment", status="failed"
            )
            provider = FakeProvider(json.dumps(AGREES))
            report = build(cfg, db, provider, source).run("run1")
            assert report.checked == 0
            assert provider.calls == 0


class TestModelDivergenceEnforcement:
    def test_stage_refuses_to_construct_when_models_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GH_TOKEN", "ghp_test")
        same = CONFIG.replace(
            "validator: {provider: anthropic, model: claude-sonnet-5}",
            "validator: {provider: anthropic, model: claude-opus-5}",
        )
        path = tmp_path / "h.yaml"
        path.write_text(same)

        from harness.config import ConfigError

        with pytest.raises(ConfigError, match="must differ"):
            load_config(path)


class TestPromptContract:
    def test_prompt_gives_the_validator_no_filing_mechanism(self) -> None:
        prompt = Path("harness/prompts/validator.md").read_text()
        assert "no mechanism" in prompt
        assert "no field in which to put one" in prompt

    def test_prompt_weights_dismissals_more_heavily(self) -> None:
        prompt = Path("harness/prompts/validator.md").read_text()
        assert "Attack dismissals harder than escalations" in prompt

    def test_prompt_discourages_manufactured_disagreement(self) -> None:
        prompt = Path("harness/prompts/validator.md").read_text()
        assert "Do not manufacture disagreement" in prompt


class TestDismissalsAreHeldToAHigherBar:
    def test_fixed_at_proven_reachability_is_also_a_contradiction(self, source: Path) -> None:
        """`fixed` closes the alert just as `not_affected` does."""
        payload = dict(VERDICT)
        payload["verdict"] = "fixed"
        payload["vex_status"] = "fixed"
        report = check_verdict(payload, bundle=BUNDLE_REACHABLE, repo_root=source, ecosystem="go")
        assert not report.passed
        assert any("contradicts reachability" in f.detail for f in report.failures)

    def test_unverifiable_citations_fail_a_dismissal(self) -> None:
        payload = dict(VERDICT)
        payload["verdict"] = "not_affected"
        payload["vex_status"] = "not_affected"
        payload["vex_justification"] = "vulnerable_code_not_in_execute_path"
        report = check_verdict(payload, repo_root=None, ecosystem="go")
        assert not report.passed
        assert any("unverifiable dismissal" in f.detail for f in report.failures)

    def test_unverifiable_citations_do_not_fail_an_escalation(self) -> None:
        """An unverified escalation costs an afternoon; an unverified dismissal costs a breach."""
        report = check_verdict(VERDICT, repo_root=None, ecosystem="go")
        assert report.passed


class TestVerdictIsNotClobbered:
    def test_validation_preserves_the_verdict_body(self, cfg: HarnessConfig, source: Path) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            build(cfg, db, FakeProvider(json.dumps(AGREES)), source).run("run1")

            stored = db.latest_verdict("k1")
            assert stored["verdict"]["verdict"] == "affected"
            assert stored["verdict"]["threat_model"]["attacker"]
            assert stored["structure_hash"] == "h1"
