"""Scanning a working tree already on disk.

`scan-public` fetches from GitHub, which needs a credential and a network. A private
mirror, an air-gapped runner, and a reviewer checking a colleague's branch all have the
code locally already. These tests pin the properties that make the local path trustworthy:
it never writes to the tree it is given, its structure hash has the same invalidation
semantics as the API-backed one, and it needs no GitHub credential at all.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from harness.config import HarnessConfig, load_config
from harness.db import Database
from harness.scan import ScanError, scan_local_repo
from harness.sources.checkout import CheckoutError
from harness.sources.local import LocalCheckout, LocalRepo, local_repo_label
from harness.sources.osv_scan import ScanStats

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
  invalidate_architecture_on_paths: ["**/go.mod", "**/package.json"]
output: {vex_dir: ./out/vex, sarif_dir: ./out/sarif}
"""

WATCHED = ("**/go.mod", "**/package.json")


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "go.mod").write_text(
        "module example.com/app\n\nrequire (\n\tgithub.com/a/b v1.2.3\n)\n"
    )
    (root / "src" / "main.go").write_text("package main\n")
    (root / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.0"}}))
    return root


@pytest.fixture()
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessConfig:
    monkeypatch.setenv("GH_TOKEN", "ghp_test")
    path = tmp_path / "harness.yaml"
    path.write_text(CONFIG)
    loaded = load_config(path)
    object.__setattr__(loaded.storage, "db_path", tmp_path / "harness.db")
    object.__setattr__(loaded.cache, "dir", tmp_path / "cache")
    return loaded


class TestStructureHash:
    """Same contract as the API-backed version: it changes exactly when a watched file's
    content or membership changes, and not on an unrelated edit."""

    def test_it_is_stable_across_calls(self, tree: Path) -> None:
        host = LocalRepo(tree)
        first = host.structure_hash("local/x", "sha", WATCHED)
        assert host.structure_hash("local/x", "sha", WATCHED) == first

    def test_editing_a_watched_file_changes_it(self, tree: Path) -> None:
        host = LocalRepo(tree)
        before = host.structure_hash("local/x", "sha", WATCHED)
        (tree / "go.mod").write_text("module example.com/app\n")
        assert host.structure_hash("local/x", "sha", WATCHED) != before

    def test_editing_an_unwatched_file_does_not(self, tree: Path) -> None:
        """Otherwise recon would be invalidated by every commit, which is the cost the
        watched-path list exists to avoid."""
        host = LocalRepo(tree)
        before = host.structure_hash("local/x", "sha", WATCHED)
        (tree / "src" / "main.go").write_text("package main\n// changed\n")
        assert host.structure_hash("local/x", "sha", WATCHED) == before

    def test_adding_a_watched_file_changes_it(self, tree: Path) -> None:
        host = LocalRepo(tree)
        before = host.structure_hash("local/x", "sha", WATCHED)
        (tree / "svc").mkdir()
        (tree / "svc" / "go.mod").write_text("module example.com/svc\n")
        assert host.structure_hash("local/x", "sha", WATCHED) != before

    def test_an_oversized_watched_file_is_marked_not_missed(self, tree: Path) -> None:
        host = LocalRepo(tree)
        before = host.structure_hash("local/x", "sha", WATCHED)
        (tree / "go.mod").write_text("x" * 5_000_000)
        assert host.structure_hash("local/x", "sha", WATCHED) != before


class TestFileText:
    def test_it_reads_a_repository_relative_file(self, tree: Path) -> None:
        assert "example.com/app" in (LocalRepo(tree).file_text("local/x", "go.mod", "sha") or "")

    def test_a_missing_file_is_none(self, tree: Path) -> None:
        assert LocalRepo(tree).file_text("local/x", "absent.txt", "sha") is None

    @pytest.mark.parametrize(
        "path", ["../outside", "a/../../b", "/etc/passwd", "a\\b", "", ".."]
    )
    def test_traversal_is_refused(self, tree: Path, path: str) -> None:
        assert LocalRepo(tree).file_text("local/x", path, "sha") is None

    def test_a_symlink_out_of_the_tree_is_refused(self, tmp_path: Path, tree: Path) -> None:
        secret = tmp_path / "secret.txt"
        secret.write_text("leaked")
        (tree / "link.txt").symlink_to(secret)
        assert LocalRepo(tree).file_text("local/x", "link.txt", "sha") is None


class TestDefaultBranchSha:
    def test_a_non_git_directory_still_yields_a_usable_revision(self, tree: Path) -> None:
        """A directory export has no HEAD, but it still needs a revision distinct from
        another revision of the same code, or verdicts would be pinned to nothing."""
        sha = LocalRepo(tree).default_branch_sha("local/x")
        assert sha and len(sha) >= 7

    def test_two_different_trees_get_different_revisions(self, tree: Path, tmp_path: Path) -> None:
        other = tmp_path / "other"
        other.mkdir()
        (other / "go.mod").write_text("module example.com/other\n")
        assert LocalRepo(tree).default_branch_sha("x") != LocalRepo(other).default_branch_sha("x")

    def test_a_git_tree_reports_its_commit(self, tree: Path) -> None:
        import subprocess

        env = {
            **__import__("os").environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.com",
        }
        subprocess.run(["git", "init", "--quiet"], cwd=tree, check=True, env=env)
        subprocess.run(["git", "add", "."], cwd=tree, check=True, env=env)
        subprocess.run(["git", "commit", "--quiet", "-m", "x"], cwd=tree, check=True, env=env)
        assert LocalRepo(tree).default_branch_sha("x") == (
            subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=tree, capture_output=True, text=True
            ).stdout.strip()
        )


class TestLocalCheckout:
    def test_ensure_returns_the_tree_it_was_given(self, tree: Path) -> None:
        checkout = LocalCheckout(tree).ensure("local/x", "sha")
        assert checkout.path == tree
        assert checkout.repo == "local/x"

    def test_it_refuses_to_evict_the_operators_working_tree(self, tree: Path) -> None:
        """Eviction is for clones the harness made. Deleting someone's checkout because a
        cleanup path ran would be catastrophic and unrecoverable."""
        with pytest.raises(CheckoutError, match="refusing to evict"):
            LocalCheckout(tree).evict("local/x", "sha")

    def test_a_missing_directory_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(CheckoutError, match="not a directory"):
            LocalCheckout(tmp_path / "absent").ensure("local/x", "sha")


class TestRepoLabel:
    def test_it_is_owner_name_shaped(self, tree: Path) -> None:
        label = local_repo_label(tree)
        assert label.count("/") == 1
        assert label.startswith("local/")

    def test_it_is_stable(self, tree: Path) -> None:
        assert local_repo_label(tree) == local_repo_label(tree)

    def test_two_trees_do_not_collide(self, tree: Path, tmp_path: Path) -> None:
        """The label is part of alert_key. Colliding labels would merge two repositories'
        alerts in one database, and the obvious collision is two checkouts with the same
        directory name."""
        other = tmp_path / "nested" / "project"
        other.mkdir(parents=True)
        (other / "go.mod").write_text("module other\n")
        assert other.name == tree.name
        assert local_repo_label(tree) != local_repo_label(other)

    def test_an_awkward_directory_name_is_slugged(self, tmp_path: Path) -> None:
        weird = tmp_path / "a b:c*d"
        weird.mkdir()
        (weird / "go.mod").write_text("module x\n")
        label = local_repo_label(weird)
        assert all(c.isalnum() or c in "/._-" for c in label)


class StubSource:
    """Stands in for the OSV source so the plumbing can be tested without a network."""

    def __init__(self, _host: object, _root: Path, *, advisories: int = 0) -> None:
        self.stats = ScanStats()
        self.stats.advisories = advisories
        self._advisories = advisories

    def default_branch_sha(self, repo: str) -> str:
        return "stubsha"

    def structure_hash(self, repo: str, sha: str, patterns: tuple[str, ...]) -> str:
        return "stub-hash"

    def file_text(self, repo: str, path: str, ref: str) -> str | None:
        return None

    def iter_alerts(self, repo: str) -> Iterator[object]:
        return iter([])

    def close(self) -> None:
        pass


class TestScanLocalRepo:
    def test_a_non_directory_is_refused(self, cfg: HarnessConfig, tmp_path: Path) -> None:
        with pytest.raises(ScanError, match="not a directory"):
            scan_local_repo(cfg, tmp_path / "absent", "r1")

    def test_it_runs_the_pipeline_with_no_github_credential(
        self,
        cfg: HarnessConfig,
        tree: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("GH_TOKEN", raising=False)
        monkeypatch.setattr("harness.scan.OsvAlertSource", StubSource)

        result = scan_local_repo(cfg, tree, "r1", use_agents=False)

        assert result.repo.startswith("local/")
        assert result.commit_sha
        assert [*result.stages] == ["ingest", "policy", "dedup", "evidence", "emit"]
        assert result.agents_enabled is False

    def test_it_records_a_run_in_the_database(
        self, cfg: HarnessConfig, tree: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("harness.scan.OsvAlertSource", StubSource)
        scan_local_repo(cfg, tree, "r1", use_agents=False)
        with Database(cfg.storage.db_path) as db:
            assert db.get_run("r1")["status"] == "complete"

    def test_it_does_not_write_to_the_tree(
        self, cfg: HarnessConfig, tree: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("harness.scan.OsvAlertSource", StubSource)
        before = {p: p.stat().st_mtime_ns for p in sorted(tree.rglob("*"))}
        scan_local_repo(cfg, tree, "r1", use_agents=False)
        assert {p: p.stat().st_mtime_ns for p in sorted(tree.rglob("*"))} == before

    def test_a_failed_stage_marks_the_run_aborted(
        self, cfg: HarnessConfig, tree: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Exploding(StubSource):
            def iter_alerts(self, repo: str) -> Iterator[object]:
                raise RuntimeError("boom")

        monkeypatch.setattr("harness.scan.OsvAlertSource", Exploding)
        with pytest.raises(RuntimeError, match="boom"):
            scan_local_repo(cfg, tree, "r1", use_agents=False)
        with Database(cfg.storage.db_path) as db:
            assert db.get_run("r1")["status"] == "aborted"
