"""The checkout walk.

A checkout is untrusted input: git materialises whatever symlinks the repository
contains, and `Path.rglob` follows a symlinked directory — so a repository holding
`loop -> .` makes a naive walk either leave the tree or never terminate.
"""

from __future__ import annotations

from pathlib import Path

from harness.fsutil import DEFAULT_SKIP_DIRS, MAX_DEPTH, iter_repo_files


def relative(root: Path, paths: list[Path]) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in paths)


class TestConfinement:
    def test_a_symlinked_directory_is_not_descended_into(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "outside-tree"
        outside.mkdir(exist_ok=True)
        (outside / "secret.txt").write_text("leak")
        root = tmp_path / "checkout"
        root.mkdir()
        (root / "linked").symlink_to(outside, target_is_directory=True)
        assert relative(root, list(iter_repo_files(root))) == []

    def test_a_symlinked_file_pointing_outside_is_not_yielded(self, tmp_path: Path) -> None:
        secret = tmp_path.parent / "secret-target.txt"
        secret.write_text("leak")
        root = tmp_path / "checkout"
        root.mkdir()
        (root / "innocent.txt").symlink_to(secret)
        assert relative(root, list(iter_repo_files(root))) == []

    def test_a_symlink_cycle_terminates(self, tmp_path: Path) -> None:
        root = tmp_path / "checkout"
        root.mkdir()
        (root / "a.txt").write_text("x")
        (root / "loop").symlink_to(root, target_is_directory=True)
        assert relative(root, list(iter_repo_files(root))) == ["a.txt"]

    def test_a_symlink_inside_the_root_is_still_yielded(self, tmp_path: Path) -> None:
        """A link that stays inside the checkout is ordinary content, not a hazard."""
        root = tmp_path / "checkout"
        root.mkdir()
        (root / "real.txt").write_text("x")
        (root / "alias.txt").symlink_to(root / "real.txt")
        assert relative(root, list(iter_repo_files(root))) == ["alias.txt", "real.txt"]


class TestFiltering:
    def test_skipped_directories_are_pruned(self, tmp_path: Path) -> None:
        (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
        (tmp_path / "node_modules" / "pkg" / "index.js").write_text("x")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("x")
        assert relative(tmp_path, list(iter_repo_files(tmp_path))) == ["src/main.py"]

    def test_a_custom_skip_set_replaces_the_default(self, tmp_path: Path) -> None:
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "v.go").write_text("x")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "m.go").write_text("x")
        found = list(iter_repo_files(tmp_path, skip_dirs=frozenset({"src"})))
        assert relative(tmp_path, found) == ["vendor/v.go"]

    def test_suffixes_filter_by_extension(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x")
        (tmp_path / "b.go").write_text("x")
        (tmp_path / "c.py").write_text("x")
        found = list(iter_repo_files(tmp_path, suffixes=(".py",)))
        assert relative(tmp_path, found) == ["a.py", "c.py"]

    def test_no_suffix_filter_yields_every_file(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x")
        (tmp_path / "b.go").write_text("x")
        assert relative(tmp_path, list(iter_repo_files(tmp_path))) == ["a.py", "b.go"]

    def test_a_missing_root_yields_nothing(self, tmp_path: Path) -> None:
        assert list(iter_repo_files(tmp_path / "nope")) == []

    def test_a_file_passed_as_the_root_yields_nothing(self, tmp_path: Path) -> None:
        target = tmp_path / "a.txt"
        target.write_text("x")
        assert list(iter_repo_files(target)) == []


class TestDeterminism:
    def test_order_is_stable_across_calls(self, tmp_path: Path) -> None:
        for name in ("z.txt", "a.txt", "m/inner.txt"):
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x")
        first = [str(p) for p in iter_repo_files(tmp_path)]
        second = [str(p) for p in iter_repo_files(tmp_path)]
        assert first == second
        assert first == sorted(first)

    def test_the_walk_is_lazy(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("x")
        walk = iter_repo_files(tmp_path)
        assert next(walk).name == "a.txt"

    def test_the_default_skip_set_is_not_empty(self) -> None:
        """An empty skip set would walk every vendored tree in every checkout."""
        assert ".git" in DEFAULT_SKIP_DIRS
        assert "node_modules" in DEFAULT_SKIP_DIRS

    def test_a_hostile_nesting_depth_terminates(self, tmp_path: Path) -> None:
        deep = tmp_path
        for index in range(MAX_DEPTH + 20):
            deep = deep / f"d{index}"
        deep.mkdir(parents=True)
        (deep / "bottom.txt").write_text("x")
        assert list(iter_repo_files(tmp_path)) == []
