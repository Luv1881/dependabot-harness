from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from harness.db import AlertRecord
from harness.ecosystems import GoAdapter, NpmAdapter
from harness.ecosystems.base import CallSite, ReachabilityLevel, ReachabilityResult
from harness.ecosystems.golang import CommandResult, parse_govulncheck
from harness.evidence import EvidenceBuilder
from harness.evidence.bundle import is_shallow
from harness.schemas import validate
from harness.util import utcnow


def alert(**kw: Any) -> AlertRecord:
    defaults: dict[str, Any] = dict(
        alert_key="a" * 64,
        repo="org/repo",
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        cve_id="CVE-2024-0001",
        purl="pkg:golang/github.com/vuln/lib",
        ecosystem="go",
        manifest_path="go.mod",
        gh_alert_num=1,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        state="open",
        resolved_ver="0.3.1",
        patched_ver="0.3.4",
        cvss_score=7.5,
        epss_score=0.043,
        in_kev=False,
        severity="high",
        symbols=["vulnlib.ParseHeader"],
    )
    defaults.update(kw)
    return AlertRecord(**defaults)


GOVULNCHECK_CALLED = (
    json.dumps({"config": {"scanner_version": "v1.1.3"}})
    + json.dumps(
        {"osv": {"id": "GO-2024-0001", "aliases": ["GHSA-aaaa-bbbb-cccc", "CVE-2024-0001"]}}
    )
    + json.dumps(
        {
            "finding": {
                "osv": "GO-2024-0001",
                "trace": [
                    {
                        "module": "github.com/vuln/lib",
                        "package": "github.com/vuln/lib",
                        "function": "ParseHeader",
                        "position": {"filename": "internal/upload/parse.go", "line": 88},
                    },
                    {
                        "module": "example.com/app",
                        "package": "example.com/app/cmd/api",
                        "function": "handleUpload",
                    },
                ],
            }
        }
    )
)

GOVULNCHECK_IMPORTED_ONLY = json.dumps(
    {"osv": {"id": "GO-2024-0001", "aliases": ["GHSA-aaaa-bbbb-cccc"]}}
) + json.dumps(
    {
        "finding": {
            "osv": "GO-2024-0001",
            "trace": [{"module": "github.com/vuln/lib", "package": "github.com/vuln/lib"}],
        }
    }
)


class TestGovulncheckParsing:
    def test_called_symbol_yields_path_from_entry(self) -> None:
        report = parse_govulncheck(GOVULNCHECK_CALLED)
        result = report.to_result({"GHSA-aaaa-bbbb-cccc"})
        assert result.level is ReachabilityLevel.PATH_FROM_ENTRY
        assert result.method == "govulncheck"
        assert result.call_sites[0].file == "internal/upload/parse.go"
        assert result.call_sites[0].line == 88
        assert result.call_sites[0].nearest_entry_point == "example.com/app/cmd/api.handleUpload"

    def test_imported_but_not_called_is_level_two(self) -> None:
        report = parse_govulncheck(GOVULNCHECK_IMPORTED_ONLY)
        result = report.to_result({"GHSA-aaaa-bbbb-cccc"})
        assert result.level is ReachabilityLevel.IMPORTED
        assert result.call_sites == []

    def test_matches_by_cve_alias(self) -> None:
        report = parse_govulncheck(GOVULNCHECK_CALLED)
        assert report.to_result({"CVE-2024-0001"}).level is ReachabilityLevel.PATH_FROM_ENTRY

    def test_advisory_the_scan_never_saw_is_not_answered(self) -> None:
        report = parse_govulncheck(GOVULNCHECK_CALLED)
        result = report.to_result({"GHSA-unrelated"})
        assert result.method == "failed"
        assert result.confidence == 0.0

    def test_tool_version_captured(self) -> None:
        assert parse_govulncheck(GOVULNCHECK_CALLED).tool_version == "v1.1.3"

    def test_empty_output_parses_to_no_findings(self) -> None:
        assert parse_govulncheck("").findings == []

    def test_malformed_output_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_govulncheck("{not json")


class TestGoAdapterToolchainFailure:
    def test_missing_go_mod_is_failure_not_absence(self, tmp_path: Path) -> None:
        result = GoAdapter().reachability(tmp_path, alert())
        assert result.method == "failed"
        assert result.confidence == 0.0
        assert result.is_failure

    def test_nonzero_exit_is_failure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "go.mod").write_text("module example.com/app\n")
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/govulncheck")

        def runner(args: list[str], *, cwd: Path, timeout: int | None = None) -> CommandResult:
            return CommandResult(returncode=1, stdout="", stderr="build failed: no go.sum")

        result = GoAdapter(runner=runner).reachability(tmp_path, alert())
        assert result.method == "failed"
        assert result.confidence == 0.0
        assert "build failed" in (result.error or "")

    def test_exit_three_is_findings_not_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "go.mod").write_text("module example.com/app\n")
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/govulncheck")

        def runner(args: list[str], *, cwd: Path, timeout: int | None = None) -> CommandResult:
            return CommandResult(returncode=3, stdout=GOVULNCHECK_CALLED, stderr="")

        result = GoAdapter(runner=runner).reachability(tmp_path, alert())
        assert result.method == "govulncheck"
        assert result.level is ReachabilityLevel.PATH_FROM_ENTRY

    def test_unparsable_stdout_is_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "go.mod").write_text("module example.com/app\n")
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/govulncheck")

        def runner(args: list[str], *, cwd: Path, timeout: int | None = None) -> CommandResult:
            return CommandResult(returncode=0, stdout="<html>proxy error</html>", stderr="")

        result = GoAdapter(runner=runner).reachability(tmp_path, alert())
        assert result.method == "failed"
        assert result.confidence == 0.0


class TestBundleInvariants:
    def test_confidence_capped_at_ecosystem_ceiling(self) -> None:
        builder = EvidenceBuilder(NpmAdapter())
        raw = ReachabilityResult(ReachabilityLevel.PATH_FROM_ENTRY, 0.99, "ts-callgraph")
        bundle = builder.build(alert(ecosystem="npm"), raw)
        assert bundle.confidence == 0.55

    def test_unknown_symbols_cap_level_and_confidence(self) -> None:
        builder = EvidenceBuilder(GoAdapter())
        raw = ReachabilityResult(ReachabilityLevel.ATTACKER_CONTROLLED, 0.95, "govulncheck")
        bundle = builder.build(alert(symbols=None), raw)
        assert bundle.level == int(ReachabilityLevel.IMPORTED)
        assert bundle.confidence == 0.5

    def test_toolchain_failure_never_reports_confidence(self) -> None:
        builder = EvidenceBuilder(GoAdapter())
        bundle = builder.build(alert(), ReachabilityResult.failed("govulncheck", "exit 1"))
        assert bundle.confidence == 0.0
        assert bundle.toolchain_failed
        assert bundle.reachability["error"]

    def test_call_sites_capped_and_flagged_truncated(self) -> None:
        sites = [CallSite(file="a.go", line=i, symbol="X") for i in range(1, 31)]
        raw = ReachabilityResult(
            ReachabilityLevel.PATH_FROM_ENTRY, 0.9, "govulncheck", call_sites=sites
        )
        bundle = EvidenceBuilder(GoAdapter()).build(alert(), raw)
        assert len(bundle.call_sites) == 15
        assert bundle.truncated is True

    def test_exactly_fifteen_is_not_truncated(self) -> None:
        sites = [CallSite(file="a.go", line=i, symbol="X") for i in range(15)]
        raw = ReachabilityResult(
            ReachabilityLevel.PATH_FROM_ENTRY, 0.9, "govulncheck", call_sites=sites
        )
        bundle = EvidenceBuilder(GoAdapter()).build(alert(), raw)
        assert bundle.truncated is False


class TestBundleSchema:
    def test_bundle_validates(self) -> None:
        report = parse_govulncheck(GOVULNCHECK_CALLED)
        raw = report.to_result({"GHSA-aaaa-bbbb-cccc"})
        bundle = EvidenceBuilder(GoAdapter()).build(alert(), raw)
        validate("evidence_bundle", bundle.to_dict())

    def test_failed_bundle_validates(self) -> None:
        bundle = EvidenceBuilder(GoAdapter()).build(
            alert(), ReachabilityResult.failed("govulncheck", "not installed")
        )
        validate("evidence_bundle", bundle.to_dict())


class TestSnippets:
    def test_window_is_bounded_and_relative(self, tmp_path: Path) -> None:
        source = tmp_path / "internal" / "upload"
        source.mkdir(parents=True)
        (source / "parse.go").write_text("\n".join(f"line{i}" for i in range(1, 101)))

        raw = ReachabilityResult(
            ReachabilityLevel.PATH_FROM_ENTRY,
            0.95,
            "govulncheck",
            call_sites=[CallSite(file="internal/upload/parse.go", line=50, symbol="Parse")],
        )
        bundle = EvidenceBuilder(GoAdapter()).build(alert(), raw, repo_root=tmp_path)
        snippet = bundle.call_sites[0]["snippet"]
        assert "line50" in snippet
        assert "line30" in snippet
        assert "line70" in snippet
        assert "line29" not in snippet

    def test_path_traversal_is_refused(self, tmp_path: Path) -> None:
        from harness.analysis import snippets

        outside = tmp_path.parent / "secret.txt"
        outside.write_text("secret")
        assert snippets.extract(tmp_path, "../secret.txt", 1).text == ""


class TestShallowDetection:
    def test_all_toolchain_failures_is_shallow(self) -> None:
        builder = EvidenceBuilder(GoAdapter())
        bundles = [
            builder.build(alert(), ReachabilityResult.failed("govulncheck", "exit 1"))
            for _ in range(3)
        ]
        assert is_shallow(bundles) is True

    def test_real_reachability_is_not_shallow(self) -> None:
        report = parse_govulncheck(GOVULNCHECK_CALLED)
        bundle = EvidenceBuilder(GoAdapter()).build(
            alert(), report.to_result({"GHSA-aaaa-bbbb-cccc"})
        )
        assert is_shallow([bundle]) is False

    def test_no_alerts_is_not_shallow(self) -> None:
        assert is_shallow([]) is False


GOVULNCHECK_UNKNOWN_ADVISORY = json.dumps(
    {"osv": {"id": "GO-2021-0067", "aliases": ["CVE-2021-27919"]}}
)


class TestAdvisoryCoverage:
    def test_advisory_the_tool_never_evaluated_is_a_failure_not_a_clearance(self) -> None:
        report = parse_govulncheck(GOVULNCHECK_UNKNOWN_ADVISORY)
        result = report.to_result({"GHSA-aaaa-bbbb-cccc"})
        assert result.method == "failed"
        assert result.confidence == 0.0
        assert "never assessed" in (result.error or "")

    def test_evaluated_advisory_with_no_finding_is_a_real_measurement(self) -> None:
        known = json.dumps({"osv": {"id": "GO-2024-0001", "aliases": ["GHSA-aaaa-bbbb-cccc"]}})
        result = parse_govulncheck(known).to_result({"GHSA-aaaa-bbbb-cccc"})
        assert result.method == "govulncheck"
        assert result.level is ReachabilityLevel.PRESENT
        assert result.confidence == 0.9

    def test_matching_works_when_advisory_has_only_a_cve_alias(self) -> None:
        only_cve = json.dumps({"osv": {"id": "GO-2021-0067", "aliases": ["CVE-2021-27919"]}})
        result = parse_govulncheck(only_cve).to_result({"CVE-2021-27919"})
        assert result.method == "govulncheck"

    def test_empty_scan_output_never_clears_an_alert(self) -> None:
        result = parse_govulncheck("").to_result({"GHSA-aaaa-bbbb-cccc"})
        assert result.method == "failed"
        assert result.confidence == 0.0


REAL_OUTPUT = (Path(__file__).parent / "fixtures" / "govulncheck_real.json").read_text()


class TestAgainstRealGovulncheckOutput:
    """Parsed against output captured from govulncheck v1.6.0 on a real vulnerable module.

    The probe module calls golang.org/x/text/language.Parse from main via handleInput,
    which govulncheck reports as GO-2021-0113 with a three-frame trace.
    """

    def test_tool_metadata(self) -> None:
        report = parse_govulncheck(REAL_OUTPUT)
        assert report.tool_version == "v1.6.0"

    def test_called_vulnerability_is_reachable_with_a_real_call_site(self) -> None:
        report = parse_govulncheck(REAL_OUTPUT)
        result = report.to_result({"GHSA-ppp9-7jff-5vj2"})
        assert result.level is ReachabilityLevel.PATH_FROM_ENTRY
        assert result.confidence == 0.95
        site = result.call_sites[0]
        assert site.symbol == "Parse"
        assert site.file.endswith("language/parse.go")
        assert site.nearest_entry_point == "example.com/probe.main"

    def test_trace_order_puts_vulnerable_symbol_first_entry_point_last(self) -> None:
        report = parse_govulncheck(REAL_OUTPUT)
        finding = next(f for f in report.findings if f.osv_id == "GO-2021-0113" and f.function)
        assert finding.function == "Parse"
        assert finding.entry_point == "example.com/probe.main"
        assert finding.trace_modules[0] == "example.com/probe"
        assert finding.trace_modules[-1] == "golang.org/x/text"

    def test_advisory_present_in_db_but_not_called(self) -> None:
        report = parse_govulncheck(REAL_OUTPUT)
        result = report.to_result({"GHSA-5rcv-m4m3-hfh7"})
        assert result.method == "govulncheck"
        assert result.level < ReachabilityLevel.PATH_FROM_ENTRY

    def test_cve_only_advisory_matches_by_cve(self) -> None:
        report = parse_govulncheck(REAL_OUTPUT)
        assert report.evaluated({"CVE-2021-27919"}) is True
        assert report.evaluated({"GHSA-not-in-this-scan"}) is False

    def test_bundle_from_real_output_validates(self) -> None:
        report = parse_govulncheck(REAL_OUTPUT)
        raw = report.to_result({"GHSA-ppp9-7jff-5vj2"})
        bundle = EvidenceBuilder(GoAdapter()).build(
            alert(ghsa_id="GHSA-ppp9-7jff-5vj2", cve_id="CVE-2021-38561"), raw
        )
        validate("evidence_bundle", bundle.to_dict())
        assert bundle.level == int(ReachabilityLevel.PATH_FROM_ENTRY)
        assert bundle.confidence == 0.95


class TestShallowRequeuePreservesDiagnostics:
    def test_the_original_toolchain_error_survives_the_shallow_flag(self, tmp_path: Path) -> None:
        import os

        from harness.config import load_config
        from harness.db import Database
        from harness.stages.evidence import EvidenceStage

        os.environ["GH_TOKEN"] = "ghp_test"
        config = tmp_path / "h.yaml"
        config.write_text(
            "github:\n  org: o\n  repos: [o/r]\n"
            "models:\n  recon: {provider: anthropic, model: claude-haiku-4-5}\n"
            "  judgment: {provider: anthropic, model: claude-opus-5}\n"
            "  validator: {provider: anthropic, model: claude-sonnet-5}\n"
            "  dedup: {provider: anthropic, model: claude-haiku-4-5}\n"
            "budgets: {per_repo_usd: 5.0, per_alert_usd: 0.4, per_run_usd: 100.0}\n"
            'cache:\n  invalidate_architecture_on_paths: ["**/go.mod"]\n'
            "output: {vex_dir: ./v, sarif_dir: ./s}\n"
        )
        cfg = load_config(config)
        object.__setattr__(cfg.storage, "db_path", tmp_path / "h.db")

        class NoCheckout:
            def ensure(self, repo: str, commit_sha: str):
                from harness.sources.checkout import CheckoutError

                raise CheckoutError("clone unavailable")

        with Database(cfg.storage.db_path) as db:
            record = alert(alert_key="c" * 64, repo="o/r")
            db.upsert_alert(record)
            db.record_snapshot("o/r", "sha1", "h1")
            db.record_stage(run_id="r1", alert_key=record.alert_key, stage="policy", status="done")

            report = EvidenceStage(cfg, db, checkouts=NoCheckout()).run("r1")

            assert report.repos[0].shallow is True
            row = db.query("SELECT error FROM stage_results WHERE stage='evidence'")[0]
            assert "shallow" in row["error"]
            assert "no checkout available" in row["error"]
            payload = db.stage_payload("r1", record.alert_key, "evidence")
            assert payload["reachability"]["method"] == "failed"


class TestShallowDistinguishesCauses:
    """A repo is shallow when the toolchain is broken, not when advisories lack symbols."""

    def build(self, **kw: Any):
        from harness.ecosystems.base import ReachabilityResult

        level = kw.pop("level", ReachabilityLevel.IMPORTED)
        symbols = kw.pop("symbols", ["pkg.Sym"])
        raw = ReachabilityResult(level, 0.9, kw.pop("method", "govulncheck"))
        return EvidenceBuilder(GoAdapter()).build(alert(symbols=symbols), raw)

    def test_advisories_without_symbols_are_not_a_broken_toolchain(self) -> None:
        bundles = [self.build(symbols=None) for _ in range(3)]
        assert all(b.reachability["method"] != "failed" for b in bundles)
        assert is_shallow(bundles) is False

    def test_a_toolchain_that_found_nothing_with_symbols_to_find_is_shallow(self) -> None:
        bundles = [self.build(symbols=["pkg.Sym"], level=ReachabilityLevel.PRESENT)]
        assert is_shallow(bundles) is True

    def test_a_mix_is_judged_on_the_measurable_ones(self) -> None:
        bundles = [
            self.build(symbols=None),
            self.build(symbols=["pkg.Sym"], level=ReachabilityLevel.PATH_FROM_ENTRY),
        ]
        assert is_shallow(bundles) is False

    def test_all_toolchain_failures_are_still_shallow(self) -> None:
        from harness.ecosystems.base import ReachabilityResult

        bundles = [
            EvidenceBuilder(GoAdapter()).build(
                alert(), ReachabilityResult.failed("govulncheck", "not installed")
            )
        ]
        assert is_shallow(bundles) is True


class TestShallowCountsCallSitesFromEveryBundle:
    def test_call_sites_rule_out_shallow_even_when_the_level_was_capped(self) -> None:
        """A capped level with real call frames is a measurement, not an empty scan."""
        from harness.ecosystems.base import ReachabilityResult

        capped = EvidenceBuilder(GoAdapter()).build(
            alert(symbols=None),
            ReachabilityResult(
                ReachabilityLevel.PATH_FROM_ENTRY,
                0.95,
                "govulncheck",
                call_sites=[CallSite(file="a.go", line=1, symbol="X")],
            ),
        )
        unreached = EvidenceBuilder(GoAdapter()).build(
            alert(symbols=["pkg.Sym"]),
            ReachabilityResult(ReachabilityLevel.PRESENT, 0.9, "govulncheck"),
        )
        assert capped.level == int(ReachabilityLevel.IMPORTED)
        assert is_shallow([capped, unreached]) is False

    def test_no_call_sites_anywhere_with_symbols_present_is_shallow(self) -> None:
        from harness.ecosystems.base import ReachabilityResult

        bundles = [
            EvidenceBuilder(GoAdapter()).build(
                alert(symbols=["pkg.Sym"]),
                ReachabilityResult(ReachabilityLevel.PRESENT, 0.9, "govulncheck"),
            )
        ]
        assert is_shallow(bundles) is True
