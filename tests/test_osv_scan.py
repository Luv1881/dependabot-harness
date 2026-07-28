from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest

from harness.sources.osv_scan import (
    OSV_ECOSYSTEMS,
    OsvAlertSource,
    ScanStats,
    discover_dependencies,
)


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class TestDiscovery:
    def test_go_mod_dependencies_are_found(self, tmp_path: Path) -> None:
        write(tmp_path, "go.mod", "module m\n\nrequire (\n\tgithub.com/a/b v1.2.3\n)\n")
        stats = ScanStats()
        found = list(discover_dependencies(tmp_path, stats))
        assert [f.dependency.name for f in found] == ["github.com/a/b"]
        assert found[0].manifest_path == "go.mod"
        assert stats.manifests == 1

    def test_unpinned_requirements_are_skipped_not_guessed(self, tmp_path: Path) -> None:
        """A range cannot be matched against an advisory's affected versions."""
        write(tmp_path, "requirements.txt", "urllib3==1.26.5\nrequests>=2.0\nflask\n")
        stats = ScanStats()
        found = list(discover_dependencies(tmp_path, stats))
        assert [f.dependency.name for f in found] == ["urllib3"]

    def test_vendored_trees_are_skipped(self, tmp_path: Path) -> None:
        write(tmp_path, "vendor/x/go.mod", "require github.com/a/b v1.0.0\n")
        assert list(discover_dependencies(tmp_path, ScanStats())) == []

    def test_nested_manifests_keep_their_path(self, tmp_path: Path) -> None:
        write(tmp_path, "services/api/go.mod", "require github.com/a/b v1.0.0\n")
        found = list(discover_dependencies(tmp_path, ScanStats()))
        assert found[0].manifest_path == "services/api/go.mod"

    def test_missing_root_yields_nothing(self, tmp_path: Path) -> None:
        assert list(discover_dependencies(tmp_path / "nope", ScanStats())) == []

    def test_every_ecosystem_maps_to_an_osv_name(self) -> None:
        from harness.sources.osv_scan import MANIFESTS

        for ecosystem in MANIFESTS.values():
            assert ecosystem in OSV_ECOSYSTEMS


class StubGithub:
    def default_branch_sha(self, repo: str) -> str:
        return "sha1"

    def structure_hash(self, repo: str, sha: str, patterns: tuple[str, ...]) -> str:
        return "h1"

    def file_text(self, repo: str, path: str, ref: str) -> str | None:
        return None

    def close(self) -> None:
        pass


class StubOsv:
    def __init__(self, advisory: Any) -> None:
        self.advisory = advisory

    def fetch(self, vuln_id: str) -> Any:
        return self.advisory


def advisory(**kw: Any) -> Any:
    from harness.sources.osv import Advisory

    defaults: dict[str, Any] = dict(
        ghsa_id="GO-2026-5970",
        summary="a flaw",
        details="",
        aliases=("CVE-2026-1",),
        symbols=(),
        raw={
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
            "affected": [
                {
                    "package": {"name": "github.com/a/b"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.9.0"}]}],
                }
            ],
        },
    )
    defaults.update(kw)
    return Advisory(**defaults)


def source_with(tmp_path: Path, handler: Any, adv: Any) -> OsvAlertSource:
    transport = httpx.MockTransport(handler)
    return OsvAlertSource(
        StubGithub(),  # type: ignore[arg-type]
        tmp_path,
        osv=StubOsv(adv),  # type: ignore[arg-type]
        client=httpx.Client(transport=transport),
    )


class TestAlertProduction:
    def test_osv_match_becomes_a_raw_alert(self, tmp_path: Path) -> None:
        write(tmp_path, "go.mod", "require github.com/a/b v1.2.3\n")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GO-2026-5970"}]}]})

        alerts = list(source_with(tmp_path, handler, advisory()).iter_alerts("org/repo"))
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.ghsa_id == "GO-2026-5970"
        assert alert.package_name == "github.com/a/b"
        assert alert.requirements == "= v1.2.3"
        assert alert.patched_version == "1.9.0"
        assert alert.manifest_path == "go.mod"

    def test_cvss_vector_is_scored(self, tmp_path: Path) -> None:
        write(tmp_path, "go.mod", "require github.com/a/b v1.2.3\n")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GO-1"}]}]})

        alert = next(iter(source_with(tmp_path, handler, advisory()).iter_alerts("org/repo")))
        assert alert.cvss_score == pytest.approx(9.8)
        assert alert.severity == "critical"

    def test_ghsa_alias_is_preferred_when_present(self, tmp_path: Path) -> None:
        write(tmp_path, "go.mod", "require github.com/a/b v1.2.3\n")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GO-1"}]}]})

        adv = advisory(aliases=("CVE-2026-1", "GHSA-aaaa-bbbb-cccc"))
        alert = next(iter(source_with(tmp_path, handler, adv).iter_alerts("org/repo")))
        assert alert.ghsa_id == "GHSA-aaaa-bbbb-cccc"

    def test_no_match_yields_no_alerts(self, tmp_path: Path) -> None:
        write(tmp_path, "go.mod", "require github.com/a/b v1.2.3\n")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": [{}]})

        assert list(source_with(tmp_path, handler, advisory()).iter_alerts("org/repo")) == []

    def test_a_failed_query_is_recorded_not_a_silent_all_clear(self, tmp_path: Path) -> None:
        """An OSV outage must not read as 'this repo has no vulnerabilities'."""
        write(tmp_path, "go.mod", "require github.com/a/b v1.2.3\n")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="Service Unavailable")

        src = source_with(tmp_path, handler, advisory())
        assert list(src.iter_alerts("org/repo")) == []
        assert src.stats.errors

    def test_query_shape_matches_the_osv_batch_api(self, tmp_path: Path) -> None:
        write(tmp_path, "go.mod", "require github.com/a/b v1.2.3\n")
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return httpx.Response(200, json={"results": [{}]})

        list(source_with(tmp_path, handler, advisory()).iter_alerts("org/repo"))
        query = captured["queries"][0]
        assert query["package"] == {"name": "github.com/a/b", "ecosystem": "Go"}
        assert query["version"] == "1.2.3"


class TestProtocolCompliance:
    def test_source_satisfies_the_alert_source_protocol(self, tmp_path: Path) -> None:
        from harness.sources import AlertSource

        src = OsvAlertSource(StubGithub(), tmp_path)  # type: ignore[arg-type]
        assert isinstance(src, AlertSource)


class TestIncompleteCoverageIsNotAnAllClear:
    """An outage must never read as 'this repository has no vulnerabilities'."""

    def test_a_failed_batch_marks_coverage_incomplete(self, tmp_path: Path) -> None:
        write(tmp_path, "go.mod", "require github.com/a/b v1.2.3\n")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="Service Unavailable")

        src = source_with(tmp_path, handler, advisory())
        assert list(src.iter_alerts("org/repo")) == []
        assert src.stats.coverage_complete is False
        assert src.stats.unqueried == 1
        assert "status is unknown" in src.stats.errors[0]

    def test_a_successful_scan_reports_complete_coverage(self, tmp_path: Path) -> None:
        write(tmp_path, "go.mod", "require github.com/a/b v1.2.3\n")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": [{}]})

        src = source_with(tmp_path, handler, advisory())
        list(src.iter_alerts("org/repo"))
        assert src.stats.coverage_complete is True
        assert src.stats.unqueried == 0

    def test_unqueried_dependencies_are_not_counted_as_queried(self, tmp_path: Path) -> None:
        write(tmp_path, "go.mod", "require github.com/a/b v1.2.3\n")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        src = source_with(tmp_path, handler, advisory())
        list(src.iter_alerts("org/repo"))
        assert src.stats.queried == 0


class TestPatchedVersionPicksTheRightBranch:
    RAW: ClassVar = {
        "affected": [
            {
                "package": {"name": "p"},
                "ranges": [
                    {"events": [{"introduced": "1.0.0"}, {"fixed": "1.9.0"}]},
                    {"events": [{"introduced": "2.0.0"}, {"fixed": "2.3.0"}]},
                ],
            }
        ]
    }

    def test_first_branch(self) -> None:
        from harness.sources.osv_scan import _patched_version

        assert _patched_version(self.RAW, "p", "1.4.2") == "1.9.0"

    def test_second_branch_is_not_given_the_first_branch_fix(self) -> None:
        from harness.sources.osv_scan import _patched_version

        assert _patched_version(self.RAW, "p", "2.1.0") == "2.3.0"

    def test_a_version_above_every_fix_has_nothing_to_upgrade_to(self) -> None:
        """Returning a lower fix would let `already_fixed` fire on the wrong branch."""
        from harness.sources.osv_scan import _patched_version

        assert _patched_version(self.RAW, "p", "3.0.0") is None

    def test_unparsable_installed_version_falls_back_to_the_lowest_fix(self) -> None:
        from harness.sources.osv_scan import _patched_version

        assert _patched_version(self.RAW, "p", "not-a-version") == "1.9.0"

    def test_other_packages_are_ignored(self) -> None:
        from harness.sources.osv_scan import _patched_version

        assert _patched_version(self.RAW, "other", "1.0.0") is None
