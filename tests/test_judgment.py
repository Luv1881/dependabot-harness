from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from harness.agents.toolbox import TOOL_DEFINITIONS, Toolbox
from harness.config import HarnessConfig, load_config
from harness.db import AlertRecord, Database
from harness.models import BudgetLedger, ModelClient, ModelRequest, ModelResponse, Usage
from harness.schemas import SchemaViolation, validate
from harness.sources.checkout import Checkout, CheckoutError
from harness.stages.judgment import JudgmentStage
from harness.util import utcnow

CONFIG = """
github:
  org: my-org
  repos: [my-org/service-a]
models:
  recon: {provider: anthropic, model: claude-haiku-4-5}
  judgment: {provider: anthropic, model: claude-opus-5, context_window: 1000000}
  validator: {provider: anthropic, model: claude-sonnet-5}
  dedup: {provider: anthropic, model: claude-haiku-4-5}
budgets:
  per_repo_usd: 5.0
  per_alert_usd: 0.4
  per_run_usd: 100.0
  judgment_max_tool_calls: 3
cache:
  invalidate_architecture_on_paths: ["**/go.mod"]
output: {vex_dir: ./out/vex, sarif_dir: ./out/sarif}
"""

VERDICT = {
    "alert_key": "k1",
    "threat_model": {
        "attacker": "unauthenticated internet client",
        "boundary_crossed": "edge -> api request body parsing",
        "assumption_broken": "parser assumes length-prefixed input is well-formed",
        "preconditions": ["service is internet-facing"],
    },
    "verdict": "affected",
    "vex_status": "affected",
    "vex_justification": None,
    "reachability_confirmed": True,
    "confidence": 0.81,
    "production_reachable": True,
    "severity_adjusted": "high",
    "severity_rationale": "CVSS 7.5 upheld",
    "evidence_cited": [
        {"file": "internal/upload/parse.go", "line": 88, "why": "reached from handleUpload"}
    ],
    "recommended_action": "bump vuln-lib to 0.3.4",
    "owner_hint": "team-platform",
    "unknowns": [],
    "needs_human": False,
}

BUNDLE = {
    "alert_key": "k1",
    "reachability": {
        "level": 4,
        "scale": {"4": "call path from an entry point to vulnerable symbol exists"},
        "confidence": 0.9,
        "method": "govulncheck",
    },
    "advisory": {"ghsa_id": "GHSA-x", "summary": "s", "affected_symbols": ["v.Parse"]},
    "exploitability": {"cvss": 7.5},
    "truncated": False,
}


class FakeProvider:
    def __init__(self, text: str) -> None:
        self.text = text
        self.calls = 0
        self.last_request: ModelRequest | None = None

    def complete(self, request: ModelRequest, model: str) -> ModelResponse:
        self.calls += 1
        self.last_request = request
        return ModelResponse(text=self.text, usage=Usage(tokens_in=4000, tokens_out=600))


class FakeCheckouts:
    def __init__(self, root: Path | None) -> None:
        self.root = root

    def ensure(self, repo: str, commit_sha: str) -> Checkout:
        if self.root is None:
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


def seed(db: Database, run_id: str = "run1", **kw: Any) -> AlertRecord:
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
        severity="high",
    )
    defaults.update(kw)
    record = AlertRecord(**defaults)
    db.upsert_alert(record)
    db.record_snapshot("my-org/service-a", "sha1", "h1")
    db.record_stage(
        run_id=run_id,
        alert_key=record.alert_key,
        stage="evidence",
        status="done",
        payload={**BUNDLE, "alert_key": record.alert_key},
    )
    return record


def build(
    cfg: HarnessConfig, db: Database, provider: FakeProvider, root: Path | None = None
) -> JudgmentStage:
    ledger = BudgetLedger(cfg.budgets, db, "run1")
    client = ModelClient(cfg.model("judgment"), ledger, provider=provider)
    return JudgmentStage(cfg, db, ledger, client=client, checkouts=FakeCheckouts(root), osv=None)


class TestVerdictSchema:
    def test_valid_verdict_passes(self) -> None:
        validate("verdict", VERDICT)

    def test_threat_model_is_required(self) -> None:
        payload = {k: v for k, v in VERDICT.items() if k != "threat_model"}
        with pytest.raises(SchemaViolation, match="threat_model"):
            validate("verdict", payload)

    def test_vacuous_threat_model_is_rejected(self) -> None:
        payload = dict(VERDICT)
        payload["threat_model"] = {
            "attacker": "",
            "boundary_crossed": "x",
            "assumption_broken": "y",
            "preconditions": [],
        }
        with pytest.raises(SchemaViolation):
            validate("verdict", payload)

    def test_not_affected_requires_a_justification(self) -> None:
        payload = dict(VERDICT)
        payload["verdict"] = "not_affected"
        payload["vex_status"] = "not_affected"
        payload["vex_justification"] = None
        with pytest.raises(SchemaViolation):
            validate("verdict", payload)

    def test_not_affected_with_a_cisa_code_passes(self) -> None:
        payload = dict(VERDICT)
        payload["verdict"] = "not_affected"
        payload["vex_status"] = "not_affected"
        payload["vex_justification"] = "vulnerable_code_not_in_execute_path"
        validate("verdict", payload)

    def test_invented_justification_is_rejected(self) -> None:
        payload = dict(VERDICT)
        payload["vex_status"] = "not_affected"
        payload["vex_justification"] = "looked_fine_to_me"
        with pytest.raises(SchemaViolation):
            validate("verdict", payload)

    def test_unknown_verdict_value_is_rejected(self) -> None:
        payload = dict(VERDICT)
        payload["verdict"] = "probably_fine"
        with pytest.raises(SchemaViolation):
            validate("verdict", payload)

    def test_evidence_line_must_be_positive(self) -> None:
        payload = dict(VERDICT)
        payload["evidence_cited"] = [{"file": "a.go", "line": 0, "why": "x"}]
        with pytest.raises(SchemaViolation):
            validate("verdict", payload)


class TestToolbox:
    def test_read_file_returns_numbered_lines(self, tmp_path: Path) -> None:
        (tmp_path / "a.go").write_text("one\ntwo\nthree\n")
        box = Toolbox(repo_root=tmp_path)
        out = box.dispatch("read_file", {"path": "a.go", "start": 2, "end": 3})
        assert "2: two" in out
        assert "3: three" in out

    def test_read_file_refuses_paths_outside_the_checkout(self, tmp_path: Path) -> None:
        secret = tmp_path.parent / "secret.txt"
        secret.write_text("credentials")
        box = Toolbox(repo_root=tmp_path)
        out = box.dispatch("read_file", {"path": "../secret.txt"})
        assert "outside the repository" in out
        assert "credentials" not in out

    def test_grep_reports_file_and_line(self, tmp_path: Path) -> None:
        (tmp_path / "a.go").write_text("package a\nfunc Parse() {}\n")
        box = Toolbox(repo_root=tmp_path)
        assert "a.go:2" in box.dispatch("grep", {"pattern": "func Parse"})

    def test_grep_invalid_regex_is_an_error_not_a_crash(self, tmp_path: Path) -> None:
        box = Toolbox(repo_root=tmp_path)
        assert "invalid regular expression" in box.dispatch("grep", {"pattern": "([unclosed"})

    def test_cap_is_enforced(self, tmp_path: Path) -> None:
        box = Toolbox(repo_root=tmp_path, max_calls=2)
        box.dispatch("grep", {"pattern": "x"})
        box.dispatch("grep", {"pattern": "y"})
        assert box.exhausted
        with pytest.raises(Exception, match="cap"):
            box.dispatch("grep", {"pattern": "z"})

    def test_unknown_tool_is_reported_not_executed(self, tmp_path: Path) -> None:
        box = Toolbox(repo_root=tmp_path)
        assert "unknown tool" in box.dispatch("run_shell", {"cmd": "rm -rf /"})

    def test_no_shell_tool_is_offered(self) -> None:
        names = {t["name"] for t in TOOL_DEFINITIONS}
        assert names == {"read_file", "grep", "fetch_advisory"}
        assert not any(n in names for n in ("bash", "shell", "exec", "write_file"))

    def test_audit_trail_records_every_call(self, tmp_path: Path) -> None:
        box = Toolbox(repo_root=tmp_path)
        box.dispatch("grep", {"pattern": "x"})
        assert box.audit()[0]["tool"] == "grep"


class TestJudgmentStage:
    def test_valid_verdict_is_stored(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            report = build(cfg, db, FakeProvider(json.dumps(VERDICT))).run("run1")

            assert report.judged == 1
            stored = db.latest_verdict("k1")
            assert stored is not None
            assert stored["verdict"]["verdict"] == "affected"
            assert stored["verdict"]["decided_by"] == "judgment"
            assert stored["structure_hash"] == "h1"

    def test_schema_violating_verdict_becomes_could_not_determine(self, cfg: HarnessConfig) -> None:
        """A malformed verdict must never be stored as if it were a decision."""
        with Database(cfg.storage.db_path) as db:
            seed(db)
            bad = {k: v for k, v in VERDICT.items() if k != "threat_model"}
            report = build(cfg, db, FakeProvider(json.dumps(bad))).run("run1")

            assert report.failed == 1
            stored = db.latest_verdict("k1")
            assert stored["verdict"]["verdict"] == "could_not_determine"
            assert stored["verdict"]["needs_human"] is True

    def test_model_failure_becomes_could_not_determine_not_a_dismissal(
        self, cfg: HarnessConfig
    ) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            provider = FakeProvider('{"error": {"type": "overloaded_error"}}')
            build(cfg, db, provider).run("run1")

            stored = db.latest_verdict("k1")
            assert stored["verdict"]["verdict"] == "could_not_determine"
            assert stored["verdict"]["confidence"] == 0.0

    def test_unparsable_response_becomes_could_not_determine(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            build(cfg, db, FakeProvider("I think it is probably fine, honestly")).run("run1")
            assert db.latest_verdict("k1")["verdict"]["verdict"] == "could_not_determine"

    def test_alerts_without_evidence_are_not_judged(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            record = seed(db)
            db.record_stage(
                run_id="run1", alert_key=record.alert_key, stage="evidence", status="failed"
            )
            provider = FakeProvider(json.dumps(VERDICT))
            report = build(cfg, db, provider).run("run1")

            assert provider.calls == 0
            assert report.judged == 0

    def test_budget_breach_defers_without_a_verdict(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            db.record_cost(
                run_id="run1",
                repo="my-org/service-a",
                stage="judgment",
                cost_usd=1.0,
                alert_key="k1",
            )
            provider = FakeProvider(json.dumps(VERDICT))
            report = build(cfg, db, provider).run("run1")

            assert provider.calls == 0
            assert report.deferred == 1
            assert db.stage_status("run1", "k1", "judgment") == "budget_deferred"
            assert db.latest_verdict("k1") is None

    def test_completed_judgment_is_not_redone(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            build(cfg, db, FakeProvider(json.dumps(VERDICT))).run("run1")
            second = FakeProvider(json.dumps(VERDICT))
            build(cfg, db, second).run("run1")
            assert second.calls == 0


class TestContextAssembly:
    def test_agent_receives_bundle_and_architecture_only(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            db.put_architecture(
                repo="my-org/service-a",
                commit_sha="sha1",
                structure_hash="h1",
                content={"summary": "edge api", "build_targets": []},
                cost_usd=0.0,
            )
            provider = FakeProvider(json.dumps(VERDICT))
            build(cfg, db, provider).run("run1")

            user = provider.last_request.user
            assert "Evidence bundle" in user
            assert "edge api" in user
            assert "govulncheck" in user

    def test_missing_architecture_is_stated_not_assumed(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            provider = FakeProvider(json.dumps(VERDICT))
            build(cfg, db, provider).run("run1")

            user = provider.last_request.user
            assert "No architecture document is cached" in user
            assert "unknown rather than assuming" in user

    def test_tool_budget_is_stated_to_the_agent(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            provider = FakeProvider(json.dumps(VERDICT))
            build(cfg, db, provider).run("run1")
            assert "at most 3 tool calls" in provider.last_request.user

    def test_tools_are_offered_to_the_model(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            seed(db)
            provider = FakeProvider(json.dumps(VERDICT))
            build(cfg, db, provider).run("run1")
            assert {t["name"] for t in provider.last_request.tools} == {
                "read_file",
                "grep",
                "fetch_advisory",
            }


class TestPromptContract:
    def test_prompt_demands_threat_model_before_filing(self) -> None:
        prompt = Path("harness/prompts/judgment.md").read_text()
        assert "State the threat model first" in prompt

    def test_prompt_rejects_tautologies_with_examples(self) -> None:
        prompt = Path("harness/prompts/judgment.md").read_text()
        assert "Reject tautologies" in prompt
        assert "database write access can write to the database" in prompt

    def test_prompt_distinguishes_exploitable_from_latent(self) -> None:
        prompt = Path("harness/prompts/judgment.md").read_text()
        assert "Exploitable now" in prompt
        assert "Real but latent" in prompt
        assert "wrong component" in prompt

    def test_prompt_makes_could_not_determine_expected(self) -> None:
        prompt = Path("harness/prompts/judgment.md").read_text()
        assert "not a failure" in prompt

    def test_prompt_requires_citations(self) -> None:
        prompt = Path("harness/prompts/judgment.md").read_text()
        assert "Cite everything" in prompt


class ToolUsingProvider:
    """Returns a tool call on the first turn, then the verdict."""

    def __init__(self, verdict: dict[str, Any], *, turns: int = 1) -> None:
        self.verdict = verdict
        self.turns = turns
        self.calls = 0
        self.histories: list[int] = []

    def complete(self, request: ModelRequest, model: str) -> ModelResponse:
        self.calls += 1
        self.histories.append(len(request.history))
        if self.calls <= self.turns:
            return ModelResponse(
                text="",
                usage=Usage(tokens_in=1000, tokens_out=100),
                tool_calls=[
                    {"name": "grep", "input": {"pattern": "Parse"}, "id": f"t{self.calls}"}
                ],
                raw_content=[
                    {
                        "type": "tool_use",
                        "id": f"t{self.calls}",
                        "name": "grep",
                        "input": {"pattern": "Parse"},
                    }
                ],
            )
        return ModelResponse(
            text=json.dumps(self.verdict), usage=Usage(tokens_in=1200, tokens_out=400)
        )


class TestToolLoopActuallyRuns:
    def test_requested_tools_are_executed_and_fed_back(
        self, cfg: HarnessConfig, tmp_path: Path
    ) -> None:
        source = tmp_path / "src"
        source.mkdir()
        (source / "parse.go").write_text("package p\nfunc Parse() {}\n")

        with Database(cfg.storage.db_path) as db:
            seed(db)
            provider = ToolUsingProvider(VERDICT, turns=1)
            report = build(cfg, db, provider, source).run("run1")

            assert provider.calls == 2
            assert provider.histories == [0, 2]
            assert report.judged == 1
            stored = db.latest_verdict("k1")
            assert stored["verdict"]["verdict"] == "affected"
            assert stored["verdict"]["tool_calls_used"] == 1

    def test_exhausting_the_tool_budget_yields_could_not_determine(
        self, cfg: HarnessConfig, tmp_path: Path
    ) -> None:
        """The cap is real: the agent does not get to answer once it is spent."""
        source = tmp_path / "src"
        source.mkdir()
        (source / "parse.go").write_text("package p\n")

        with Database(cfg.storage.db_path) as db:
            seed(db)
            provider = ToolUsingProvider(VERDICT, turns=99)
            report = build(cfg, db, provider, source).run("run1")

            stored = db.latest_verdict("k1")
            assert stored["verdict"]["verdict"] == "could_not_determine"
            assert stored["verdict"]["needs_human"] is True
            assert stored["verdict"]["tool_calls_used"] == 3
            assert report.cap_reached == 1

    def test_tool_audit_is_recorded_on_the_verdict(
        self, cfg: HarnessConfig, tmp_path: Path
    ) -> None:
        source = tmp_path / "src"
        source.mkdir()
        (source / "parse.go").write_text("package p\nfunc Parse() {}\n")

        with Database(cfg.storage.db_path) as db:
            seed(db)
            build(cfg, db, ToolUsingProvider(VERDICT, turns=1), source).run("run1")
            audit = db.latest_verdict("k1")["verdict"]["tool_audit"]
            assert audit[0]["tool"] == "grep"

    def test_a_tool_only_response_is_not_treated_as_an_empty_failure(self) -> None:
        from harness.models import ResponseClass, classify

        assert classify("", has_tool_calls=True).kind is ResponseClass.OK
        assert classify("", has_tool_calls=False).kind is ResponseClass.EMPTY
