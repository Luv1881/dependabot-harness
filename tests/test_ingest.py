"""M1 acceptance tests: cache replay, resume, and structure-hash invalidation.

The GitHub/OSV/EPSS/KEV clients are faked so ingest is exercised end to end with no
network. The fakes count calls, which is how the "$0 and no re-work on the second run"
gate is actually verified rather than asserted.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from harness.config import HarnessConfig, load_config
from harness.db import Database
from harness.sources.github import RawAlert
from harness.sources.osv import Advisory
from harness.stages.ingest import IngestStage

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
  verdict_ttl_days: 90
  invalidate_architecture_on_paths: ["**/go.mod"]
output: {vex_dir: ./out/vex, sarif_dir: ./out/sarif}
"""

GO_MOD = """
module example.com/app
go 1.22
require (
\tgithub.com/vuln/lib v0.3.1
\tgithub.com/other/dep v1.0.0 // indirect
)
"""


class FakeGithub:
    def __init__(self, alerts: list[RawAlert], *, sha: str = "sha1", structure: str = "h1") -> None:
        self.alerts = alerts
        self.sha = sha
        self.structure = structure
        self.calls: dict[str, int] = {"alerts": 0, "tree": 0, "file": 0}

    def default_branch_sha(self, repo: str) -> str:
        return self.sha

    def structure_hash(self, repo: str, sha: str, patterns: tuple[str, ...]) -> str:
        self.calls["tree"] += 1
        return self.structure

    def iter_alerts(self, repo: str) -> Iterator[RawAlert]:
        self.calls["alerts"] += 1
        yield from (a for a in self.alerts if a.repo == repo)

    def file_text(self, repo: str, path: str, ref: str) -> str | None:
        self.calls["file"] += 1
        return GO_MOD if path.endswith("go.mod") else None

    def close(self) -> None:
        pass


class FakeOsv:
    def __init__(self, symbols: tuple[str, ...] = ("vulnlib.ParseHeader",)) -> None:
        self.symbols = symbols
        self.calls = 0

    def fetch(self, vuln_id: str) -> Advisory | None:
        self.calls += 1
        return Advisory(
            ghsa_id=vuln_id,
            summary="test advisory",
            details="",
            aliases=("CVE-2024-0001",),
            symbols=self.symbols,
        )

    def close(self) -> None:
        pass


class FakeEpss:
    def score(self, cve_id: str) -> float | None:
        return 0.043

    def close(self) -> None:
        pass


class FakeKev:
    def __init__(self, members: set[str] | None = None) -> None:
        self.members = members or set()

    def contains(self, cve_id: str | None) -> bool:
        return bool(cve_id and cve_id in self.members)

    def close(self) -> None:
        pass


def make_raw(
    *,
    ghsa: str = "GHSA-aaaa-bbbb-cccc",
    manifest: str = "go.mod",
    package: str = "github.com/vuln/lib",
    requirements: str = "= 0.3.1",
    repo: str = "my-org/service-a",
) -> RawAlert:
    return RawAlert(
        repo=repo,
        number=7,
        state="open",
        created_at="2026-01-01T00:00:00Z",
        manifest_path=manifest,
        requirements=requirements,
        scope_hint="runtime",
        ghsa_id=ghsa,
        cve_id="CVE-2024-0001",
        package_name=package,
        ecosystem="go",
        patched_version="0.3.4",
        vulnerable_range="< 0.3.4",
        severity="high",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N",
        summary="test",
    )


@pytest.fixture()
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessConfig:
    monkeypatch.setenv("GH_TOKEN", "ghp_test")
    path = tmp_path / "harness.yaml"
    path.write_text(CONFIG)
    loaded = load_config(path)
    object.__setattr__(loaded.storage, "db_path", tmp_path / "harness.db")
    object.__setattr__(loaded.cache, "dir", tmp_path / "cache")
    return loaded


def build(cfg: HarnessConfig, db: Database, github: FakeGithub, **kw: Any) -> IngestStage:
    return IngestStage(
        cfg,
        db,
        github=github,  # type: ignore[arg-type]
        osv=kw.get("osv") or FakeOsv(),  # type: ignore[arg-type]
        epss=kw.get("epss") or FakeEpss(),  # type: ignore[arg-type]
        kev=kw.get("kev") or FakeKev(),  # type: ignore[arg-type]
    )


class TestEnrichment:
    def test_alert_is_fully_enriched(self, cfg: HarnessConfig) -> None:
        with Database(cfg.storage.db_path) as db:
            stage = build(cfg, db, FakeGithub([make_raw()]))
            stage.run("run1")
            alert = db.alerts_for_repo("my-org/service-a")[0]

        assert alert.purl == "pkg:golang/github.com/vuln/lib"
        assert alert.resolved_ver == "0.3.1"
        assert alert.patched_ver == "0.3.4"
        assert alert.cve_id == "CVE-2024-0001"
        assert alert.epss_score == 0.043
        assert alert.in_kev is False
        assert alert.symbols == ["vulnlib.ParseHeader"]
        assert alert.symbols_known

    def test_scope_resolved_from_manifest_not_payload(self, cfg: HarnessConfig) -> None:
        """§5.4 — Dependabot's own scope hint is unreliable for transitives."""
        indirect = make_raw(package="github.com/other/dep", requirements="= 1.0.0")
        with Database(cfg.storage.db_path) as db:
            build(cfg, db, FakeGithub([indirect])).run("run1")
            alert = db.alerts_for_repo("my-org/service-a")[0]
            scope_source = db.stage_payload("run1", alert.alert_key, "ingest")["scope_source"]
        assert alert.is_direct is False
        assert scope_source == "go.mod:require"

    def test_unreadable_manifest_yields_unknown_not_runtime(self, cfg: HarnessConfig) -> None:
        raw = make_raw(manifest="missing/go.mod.bak")
        with Database(cfg.storage.db_path) as db:
            build(cfg, db, FakeGithub([raw])).run("run1")
            alert = db.alerts_for_repo("my-org/service-a")[0]
        assert alert.dep_scope == "unknown"
        assert alert.is_direct is None

    def test_advisory_without_symbols_is_recorded_as_such(self, cfg: HarnessConfig) -> None:
        """§14.5 — empty symbols is the signal that caps reachability downstream."""
        with Database(cfg.storage.db_path) as db:
            build(cfg, db, FakeGithub([make_raw()]), osv=FakeOsv(symbols=())).run("run1")
            alert = db.alerts_for_repo("my-org/service-a")[0]
            payload = db.stage_payload("run1", alert.alert_key, "ingest")
        assert alert.symbols_known is False
        assert payload["symbols_known"] is False


class TestCacheReplay:
    """M1 accept gate: the second run replays everything and does no work."""

    def test_second_run_replays_100_percent(self, cfg: HarnessConfig) -> None:
        github = FakeGithub([make_raw()])
        with Database(cfg.storage.db_path) as db:
            first = build(cfg, db, github).run("run1")
            assert first.cache_replay_rate == 0.0
            assert first.ingested == 1

            key = db.alerts_for_repo("my-org/service-a")[0].alert_key
            db.put_verdict(
                alert_key=key,
                run_id="run1",
                verdict={"verdict": "not_affected"},
                structure_hash="h1",
            )

            second = build(cfg, db, github).run("run2")

        assert second.total == 1
        assert second.replayed == 1
        assert second.cache_replay_rate == 1.0

    def test_replay_copies_prior_verdict_forward(self, cfg: HarnessConfig) -> None:
        github = FakeGithub([make_raw()])
        with Database(cfg.storage.db_path) as db:
            build(cfg, db, github).run("run1")
            key = db.alerts_for_repo("my-org/service-a")[0].alert_key
            db.put_verdict(
                alert_key=key,
                run_id="run1",
                verdict={"verdict": "not_affected"},
                validated=True,
                structure_hash="h1",
            )

            build(cfg, db, github).run("run2")
            rows = db.query("SELECT run_id FROM verdicts WHERE alert_key=?", (key,))

        assert {r["run_id"] for r in rows} == {"run1", "run2"}

    def test_second_run_costs_nothing(self, cfg: HarnessConfig) -> None:
        github = FakeGithub([make_raw()])
        with Database(cfg.storage.db_path) as db:
            build(cfg, db, github).run("run1")
            key = db.alerts_for_repo("my-org/service-a")[0].alert_key
            db.put_verdict(
                alert_key=key, run_id="run1", verdict={"verdict": "fixed"}, structure_hash="h1"
            )
            build(cfg, db, github).run("run2")
            assert db.spend("run2") == 0.0

    def test_changed_structure_hash_defeats_replay(self, cfg: HarnessConfig) -> None:
        """A fresh verdict against a changed dependency surface is not evidence."""
        with Database(cfg.storage.db_path) as db:
            build(cfg, db, FakeGithub([make_raw()], sha="sha1", structure="h1")).run("run1")
            key = db.alerts_for_repo("my-org/service-a")[0].alert_key
            db.put_verdict(
                alert_key=key,
                run_id="run1",
                verdict={"verdict": "not_affected"},
                structure_hash="h1",
            )

            changed = FakeGithub([make_raw()], sha="sha2", structure="h2")
            second = build(cfg, db, changed).run("run2")

        assert second.replayed == 0
        assert second.ingested == 1
        assert second.repos[0].structure_changed is True

    def test_unwatched_commit_does_not_invalidate(self, cfg: HarnessConfig) -> None:
        """§8 — recon is not invalidated on every commit, only on watched paths."""
        with Database(cfg.storage.db_path) as db:
            build(cfg, db, FakeGithub([make_raw()], sha="sha1", structure="h1")).run("run1")
            key = db.alerts_for_repo("my-org/service-a")[0].alert_key
            db.put_verdict(
                alert_key=key,
                run_id="run1",
                verdict={"verdict": "not_affected"},
                structure_hash="h1",
            )

            moved = FakeGithub([make_raw()], sha="sha2", structure="h1")
            second = build(cfg, db, moved).run("run2")

        assert second.replayed == 1
        assert second.repos[0].structure_changed is False

    def test_expired_verdict_is_not_replayed(self, cfg: HarnessConfig) -> None:
        github = FakeGithub([make_raw()])
        with Database(cfg.storage.db_path) as db:
            build(cfg, db, github).run("run1")
            key = db.alerts_for_repo("my-org/service-a")[0].alert_key
            db.put_verdict(
                alert_key=key,
                run_id="run1",
                verdict={"verdict": "not_affected"},
                structure_hash="h1",
            )
            db.query(
                "UPDATE verdicts SET created_at='2020-01-01T00:00:00+00:00' WHERE alert_key=?",
                (key,),
            )
            second = build(cfg, db, github).run("run2")
        assert second.replayed == 0


class TestResume:
    def test_completed_stage_is_never_redone(self, cfg: HarnessConfig) -> None:
        """§4 — resume picks up exactly where a killed process stopped."""
        github = FakeGithub([make_raw()])
        with Database(cfg.storage.db_path) as db:
            build(cfg, db, github).run("run1")
            osv = FakeOsv()
            build(cfg, db, github, osv=osv).run("run1")
            assert osv.calls == 0

    def test_resume_preserves_replay_accounting(self, cfg: HarnessConfig) -> None:
        github = FakeGithub([make_raw()])
        with Database(cfg.storage.db_path) as db:
            build(cfg, db, github).run("run1")
            key = db.alerts_for_repo("my-org/service-a")[0].alert_key
            db.put_verdict(
                alert_key=key, run_id="run1", verdict={"verdict": "fixed"}, structure_hash="h1"
            )
            build(cfg, db, github).run("run2")
            resumed = build(cfg, db, github).run("run2")
        assert resumed.replayed == 1
        assert resumed.ingested == 0

    def test_failed_alert_is_retried_on_resume(self, cfg: HarnessConfig) -> None:
        class BrokenOsv(FakeOsv):
            def fetch(self, vuln_id: str) -> Advisory | None:
                self.calls += 1
                raise RuntimeError("OSV unavailable")

        github = FakeGithub([make_raw()])
        with Database(cfg.storage.db_path) as db:
            first = build(cfg, db, github, osv=BrokenOsv()).run("run1")
            assert first.failed == 1
            assert db.alerts_for_repo("my-org/service-a") == []

            second = build(cfg, db, github).run("run1")
            assert second.ingested == 1


class TestMonorepo:
    def test_same_advisory_in_two_manifests_is_two_alerts(self, cfg: HarnessConfig) -> None:
        """§14.4 — alert_key includes manifest_path for exactly this case."""
        alerts = [
            make_raw(manifest="services/api/go.mod"),
            make_raw(manifest="services/worker/go.mod"),
        ]
        with Database(cfg.storage.db_path) as db:
            report = build(cfg, db, FakeGithub(alerts)).run("run1")
            keys = {a.alert_key for a in db.alerts_for_repo("my-org/service-a")}
        assert report.ingested == 2
        assert len(keys) == 2
