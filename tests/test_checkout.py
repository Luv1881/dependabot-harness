"""Checkout manager: credential hygiene, argument validation, and failure semantics.

These tests exercise real `git` against a local origin rather than a mock, because the
defect they exist for — a token written into `.git/config` — is a property of what git
does with the arguments it is handed, and a mock would assert the wrong thing.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from harness.config import GithubConfig
from harness.sources import checkout as checkout_module
from harness.sources.checkout import CheckoutError, CheckoutManager

TOKEN = "ghs_SUPERSECRETTOKENVALUE0123456789"


@pytest.fixture()
def origin(tmp_path: Path) -> Iterator[tuple[Path, str]]:
    """A real single-commit git repository, and the SHA of its head."""
    repo = tmp_path / "origin"
    repo.mkdir()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    _git(["init", "--quiet", "-b", "main"], cwd=repo, env=env)
    (repo / "README.md").write_text("hello\n")
    _git(["add", "."], cwd=repo, env=env)
    _git(["commit", "--quiet", "-m", "initial"], cwd=repo, env=env)
    sha = _git(["rev-parse", "HEAD"], cwd=repo, env=env).strip()
    yield repo, sha


def _git(args: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True, env=env
    )
    return proc.stdout


def _manager(root: Path, *, token: str | None = TOKEN) -> CheckoutManager:
    github = GithubConfig(org="o", repos=("o/r",), token=token)
    return CheckoutManager(root, github)


def _local(manager: CheckoutManager, origin: Path) -> None:
    """Point the manager at a local origin so no test touches the network."""
    manager._remote_url = lambda repo: f"file://{origin}"  # type: ignore[method-assign]


class TestCredentialsNeverReachTheDisk:
    def test_a_clone_succeeds_and_the_token_is_absent_from_git_config(
        self, tmp_path: Path, origin: tuple[Path, str]
    ) -> None:
        """A credential embedded in a remote URL is persisted in plaintext to
        `.git/config`, where it outlives the clone and is readable by anything that can
        read the checkout directory."""
        repo, sha = origin
        manager = _manager(tmp_path / "checkouts")
        _local(manager, repo)

        checkout = manager.ensure("o/r", sha)

        assert (checkout.path / "README.md").read_text().strip() == "hello"
        config = (checkout.path / ".git" / "config").read_text()
        assert TOKEN not in config
        assert "extraheader" not in config.lower()

    def test_the_remote_url_carries_no_credential(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path / "checkouts")
        url = manager._remote_url("o/r")
        assert url == "https://github.com/o/r.git"
        assert TOKEN not in url

    def test_authentication_is_supplied_per_invocation(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path / "checkouts")
        args = manager._auth_args()
        assert args[0] == "-c"
        assert args[1].startswith("http.extraHeader=Authorization: Basic ")
        assert TOKEN not in args[1], "the header is base64, never the raw token"
        import base64

        decoded = base64.b64decode(args[1].split("Basic ", 1)[1]).decode()
        assert decoded == f"x-access-token:{TOKEN}"

    def test_no_credential_means_no_auth_arguments(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path / "checkouts", token=None)
        assert manager._auth_args() == []


class TestErrorMessagesAreRedacted:
    @pytest.mark.parametrize(
        "message",
        [
            f"fatal: could not read Username for 'https://x-access-token:{TOKEN}@github.com'",
            f"remote: invalid credentials for {TOKEN}",
            f"Authorization: Bearer {TOKEN} rejected",
        ],
    )
    def test_the_token_never_appears_in_a_raised_message(self, message: str) -> None:
        assert TOKEN not in checkout_module._redact(message, (TOKEN,))

    def test_an_unrecognised_shape_containing_the_prefix_is_still_scrubbed(self) -> None:
        out = checkout_module._redact("x-access-token:whatever", (None,))
        assert "whatever" not in out


class TestArgumentValidation:
    """`repo` and `ref` become both a path component and a git argument."""

    @pytest.mark.parametrize(
        ("repo", "ref"),
        [
            ("../../etc", "abc123"),
            ("o/../../etc", "abc123"),
            ("noslash", "abc123"),
            ("", "abc123"),
            ("o/..", "abc123"),
            ("o/.", "abc123"),
            ("o/r", "-upload-pack=evil"),
            ("o/r", "../../etc/passwd"),
            ("o/r", ""),
            ("o/r", "a b"),
        ],
    )
    def test_a_hostile_repo_or_ref_is_refused(self, tmp_path: Path, repo: str, ref: str) -> None:
        manager = _manager(tmp_path / "checkouts")
        with pytest.raises(CheckoutError):
            manager.ensure(repo, ref)

    @pytest.mark.parametrize("ref", ["abc1234", "main", "refs/tags/v1.0.0", "v1.2.3-rc.1"])
    def test_ordinary_refs_are_accepted(self, tmp_path: Path, ref: str) -> None:
        manager = _manager(tmp_path / "checkouts")
        manager._validate("o/r", ref)

    def test_a_refused_path_never_leaves_the_checkout_root(self, tmp_path: Path) -> None:
        root = tmp_path / "checkouts"
        manager = _manager(root)
        with pytest.raises(CheckoutError):
            manager.ensure("..", "abc123")
        assert list(root.iterdir()) == []


class TestFailureSemantics:
    def test_a_missing_git_binary_is_a_checkout_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda _: None)
        manager = _manager(tmp_path / "checkouts")
        with pytest.raises(CheckoutError, match="git not found"):
            manager.ensure("o/r", "abc123")

    def test_a_failed_fetch_is_a_checkout_error_and_leaves_no_partial_directory(
        self, tmp_path: Path
    ) -> None:
        manager = _manager(tmp_path / "checkouts")
        manager._remote_url = lambda repo: f"file://{tmp_path}/nonexistent"  # type: ignore[method-assign]
        with pytest.raises(CheckoutError):
            manager.ensure("o/r", "deadbeef")
        target = tmp_path / "checkouts" / "o__r"
        targets = [
            p for p in target.iterdir() if p.name.startswith(".")
        ] if target.exists() else []
        assert targets == []

    def test_a_cached_checkout_is_reused_without_cloning(
        self, tmp_path: Path, origin: tuple[Path, str]
    ) -> None:
        repo, sha = origin
        manager = _manager(tmp_path / "checkouts")
        _local(manager, repo)

        first = manager.ensure("o/r", sha)
        manager._remote_url = lambda repo: f"file://{tmp_path}/now-gone"  # type: ignore[method-assign]
        second = manager.ensure("o/r", sha)
        assert first.path == second.path

    def test_a_git_subprocess_cannot_run_unbounded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def hang(*args: object, **kwargs: object) -> object:
            raise subprocess.TimeoutExpired(cmd="git", timeout=1)

        monkeypatch.setattr("subprocess.run", hang)
        with pytest.raises(CheckoutError, match="timed out"):
            checkout_module._git(["fetch"], cwd=tmp_path)

    def test_a_git_subprocess_is_given_a_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, object] = {}
        real = subprocess.run

        def spy(*args: object, **kwargs: object) -> object:
            seen.update(kwargs)
            return real(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr("subprocess.run", spy)
        checkout_module._git(["--version"], cwd=tmp_path)
        assert seen.get("timeout") == checkout_module._CLONE_TIMEOUT_SECONDS


class TestTheStandardLibraryAlwaysShips:
    """`go list` reports an empty module path for standard-library packages, because they
    belong to no module. Leaving them out of the artifact set would let `not_imported`
    clear a stdlib advisory on the grounds that nothing "imports stdlib" — while the
    standard library is the one thing always linked in."""

    def test_stdlib_is_added_to_a_go_shipped_set(self, tmp_path: Path) -> None:
        from harness.analysis.shipped import _STDLIB, go_shipped

        module = tmp_path / "m"
        module.mkdir()
        (module / "go.mod").write_text("module example.com/m\n\ngo 1.25.8\n")
        (module / "main.go").write_text(
            'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println() }\n'
        )
        shipped = go_shipped(module)
        assert shipped is not None
        assert _STDLIB in shipped

    def test_a_directory_without_a_module_answers_nothing(self, tmp_path: Path) -> None:
        from harness.analysis.shipped import go_shipped

        assert go_shipped(tmp_path) is None
