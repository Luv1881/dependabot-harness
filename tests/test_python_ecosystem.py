from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from harness.analysis.pycallgraph import analyze
from harness.db import AlertRecord
from harness.ecosystems import PythonAdapter
from harness.ecosystems.base import ReachabilityLevel
from harness.ecosystems.golang import CommandResult
from harness.evidence import EvidenceBuilder
from harness.schemas import validate
from harness.util import utcnow


def alert(**kw: Any) -> AlertRecord:
    defaults: dict[str, Any] = dict(
        alert_key="b" * 64,
        repo="org/repo",
        ghsa_id="GHSA-py-1234",
        cve_id="CVE-2024-9999",
        purl="pkg:pypi/urllib3",
        ecosystem="pip",
        manifest_path="requirements.txt",
        gh_alert_num=1,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        state="open",
        resolved_ver="1.0.0",
        patched_ver="2.0.0",
        symbols=["urllib3.util.retry.Retry"],
    )
    defaults.update(kw)
    return AlertRecord(**defaults)


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class TestAstAnalysis:
    def test_plain_import_recorded(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "import urllib3\n")
        assert analyze(tmp_path).imports_module("urllib3")

    def test_from_import_recorded(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "from urllib3.util import retry\n")
        assert analyze(tmp_path).imports_module("urllib3")

    def test_absent_module_reports_false(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "import os\n")
        assert not analyze(tmp_path).imports_module("urllib3")

    def test_call_site_has_file_and_line(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "from urllib3.util.retry import Retry\n\nr = Retry(3)\n")
        references = analyze(tmp_path).references_symbol("urllib3.util.retry.Retry")
        assert references
        assert references[0].file == "a.py"
        assert references[0].line == 3

    def test_attribute_style_call_matches(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "import urllib3\n\nx = urllib3.util.retry.Retry(3)\n")
        assert analyze(tmp_path).references_symbol("urllib3.util.retry.Retry")

    def test_unrelated_symbol_does_not_match(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "import urllib3\n\nx = urllib3.PoolManager()\n")
        assert not analyze(tmp_path).references_symbol("urllib3.util.retry.Retry")

    def test_unparsable_file_is_recorded_not_ignored(self, tmp_path: Path) -> None:
        write(tmp_path, "good.py", "import os\n")
        write(tmp_path, "bad.py", "def broken(:\n")
        result = analyze(tmp_path)
        assert result.parsed_files == 1
        assert "bad.py" in result.unparsable_files

    def test_dynamic_import_is_flagged(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "import importlib\n\nm = importlib.import_module('urllib3')\n")
        assert analyze(tmp_path).uses_dynamic_import

    def test_virtualenvs_are_skipped(self, tmp_path: Path) -> None:
        write(tmp_path, ".venv/lib/dep.py", "import urllib3\n")
        write(tmp_path, "a.py", "import os\n")
        assert not analyze(tmp_path).imports_module("urllib3")

    def test_empty_tree_is_not_scanned(self, tmp_path: Path) -> None:
        assert not analyze(tmp_path).scanned


class TestPythonReachability:
    def test_missing_checkout_is_a_failure_not_absence(self) -> None:
        result = PythonAdapter().reachability(Path("/nonexistent"), alert())
        assert result.method == "failed"
        assert result.confidence == 0.0

    def test_no_python_sources_is_a_failure(self, tmp_path: Path) -> None:
        write(tmp_path, "README.md", "no code here")
        result = PythonAdapter().reachability(tmp_path, alert())
        assert result.method == "failed"
        assert result.confidence == 0.0

    def test_package_never_imported_is_level_one(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "import os\n")
        result = PythonAdapter().reachability(tmp_path, alert())
        assert result.level is ReachabilityLevel.PRESENT
        assert result.method != "failed"

    def test_imported_but_symbol_unused_is_level_two(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "import urllib3\n\nx = urllib3.PoolManager()\n")
        result = PythonAdapter().reachability(tmp_path, alert())
        assert result.level is ReachabilityLevel.IMPORTED

    def test_symbol_referenced_is_level_three_with_a_call_site(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "from urllib3.util.retry import Retry\n\nr = Retry(3)\n")
        result = PythonAdapter().reachability(tmp_path, alert())
        assert result.level is ReachabilityLevel.SYMBOL_REFERENCED
        assert result.call_sites[0].file == "a.py"
        assert result.call_sites[0].line == 3

    def test_dynamic_import_lowers_confidence(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "a.py",
            "import importlib\nfrom urllib3.util.retry import Retry\n\n"
            "r = Retry(3)\nm = importlib.import_module('x')\n",
        )
        result = PythonAdapter().reachability(tmp_path, alert())
        assert result.confidence <= 0.5

    def test_confidence_never_exceeds_the_python_ceiling(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "from urllib3.util.retry import Retry\n\nr = Retry(3)\n")
        adapter = PythonAdapter()
        raw = adapter.reachability(tmp_path, alert())
        clamped = adapter.clamp(raw, symbols_known=True)
        assert clamped.confidence <= adapter.confidence_ceiling()
        assert adapter.confidence_ceiling() == 0.75


class TestOsvScannerIntegration:
    def test_scanner_absent_falls_back_to_ast_alone(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "from urllib3.util.retry import Retry\n\nr = Retry(3)\n")
        result = PythonAdapter().reachability(tmp_path, alert())
        assert result.method in {"ast", "osv-scanner+ast"}
        assert result.method != "failed"

    def test_scanner_call_analysis_raises_the_level(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        write(tmp_path, "a.py", "from urllib3.util.retry import Retry\n\nr = Retry(3)\n")
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/osv-scanner")

        payload = (
            '{"results": [{"packages": [{"vulnerabilities": '
            '[{"id": "GHSA-py-1234", "aliases": ["GHSA-py-1234"]}], '
            '"groups": [{"experimentalAnalysis": {"called": true}}]}]}]}'
        )

        def runner(args: list[str], *, cwd: Path, timeout: int | None = None) -> CommandResult:
            return CommandResult(returncode=1, stdout=payload, stderr="")

        result = PythonAdapter(runner=runner).reachability(tmp_path, alert())
        assert result.level is ReachabilityLevel.PATH_FROM_ENTRY
        assert result.method == "osv-scanner+ast"

    def test_scanner_crash_does_not_invent_reachability(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        write(tmp_path, "a.py", "import os\n")
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/osv-scanner")

        def runner(args: list[str], *, cwd: Path, timeout: int | None = None) -> CommandResult:
            return CommandResult(returncode=127, stdout="", stderr="segfault")

        result = PythonAdapter(runner=runner).reachability(tmp_path, alert())
        assert result.level is ReachabilityLevel.PRESENT
        assert result.method == "ast"


class TestPythonEvidenceBundle:
    def test_bundle_validates(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "from urllib3.util.retry import Retry\n\nr = Retry(3)\n")
        adapter = PythonAdapter()
        raw = adapter.reachability(tmp_path, alert())
        bundle = EvidenceBuilder(adapter).build(alert(), raw, repo_root=tmp_path)
        validate("evidence_bundle", bundle.to_dict())
        assert bundle.confidence <= 0.75

    def test_unknown_symbols_cap_applies(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "from urllib3.util.retry import Retry\n\nr = Retry(3)\n")
        adapter = PythonAdapter()
        raw = adapter.reachability(tmp_path, alert(symbols=None))
        bundle = EvidenceBuilder(adapter).build(alert(symbols=None), raw)
        assert bundle.level <= int(ReachabilityLevel.IMPORTED)
        assert bundle.confidence <= 0.5

    def test_failed_scan_bundle_is_zero_confidence(self) -> None:
        adapter = PythonAdapter()
        raw = adapter.reachability(Path("/nonexistent"), alert())
        bundle = EvidenceBuilder(adapter).build(alert(), raw)
        validate("evidence_bundle", bundle.to_dict())
        assert bundle.toolchain_failed
        assert bundle.confidence == 0.0


class TestAliasedImports:
    def test_from_import_as_is_resolved(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "from urllib3.util.retry import Retry as R\n\nx = R(3)\n")
        references = analyze(tmp_path).references_symbol("urllib3.util.retry.Retry")
        assert references
        assert references[0].line == 3

    def test_module_import_as_is_resolved(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "import urllib3.util.retry as retrymod\n\nx = retrymod.Retry(3)\n")
        assert analyze(tmp_path).references_symbol("urllib3.util.retry.Retry")

    def test_aliased_call_raises_the_reachability_level(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "from urllib3.util.retry import Retry as R\n\nx = R(3)\n")
        result = PythonAdapter().reachability(tmp_path, alert())
        assert result.level is ReachabilityLevel.SYMBOL_REFERENCED

    def test_an_unrelated_alias_does_not_match(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "from os import path as R\n\nx = R.join('a')\n")
        assert not analyze(tmp_path).references_symbol("urllib3.util.retry.Retry")
