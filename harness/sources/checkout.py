"""Read-only, content-addressed repository checkouts.

The spec never says where repo source comes from, but §6 (`not_imported`) and §9
(evidence assembly) both need a working tree. This module is that answer: a shallow
clone per commit SHA, cached, never written to.

The harness has read-only access to source (§17). Nothing here mutates a checkout after
it is created, and callers get the path only.

Credentials never touch the disk. A token embedded in a remote URL is written in
plaintext to `.git/config`, where it survives the clone and is readable by anything that
can read the checkout directory, so authentication is supplied per invocation instead.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..config import GithubConfig, valid_repo

_CLONE_TIMEOUT_SECONDS = 600
"""No git subprocess may run unbounded. A hung fetch hangs the whole run otherwise."""

_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")


class CheckoutError(RuntimeError):
    """Clone or fetch failed. Callers must treat this as 'we could not tell', never as
    'the code is not there' (§14.3)."""


@dataclass(frozen=True)
class Checkout:
    repo: str
    commit_sha: str
    path: Path


class CheckoutManager:
    def __init__(self, root: str | Path, github: GithubConfig) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._github = github

    def _dir(self, repo: str, commit_sha: str) -> Path:
        return self.root / repo.replace("/", "__") / commit_sha

    def _token(self) -> str | None:
        return self._github.token or os.environ.get("GH_TOKEN")

    @staticmethod
    def _remote_url(repo: str) -> str:
        return f"https://github.com/{repo}.git"

    def _auth_args(self) -> list[str]:
        """Per-invocation credentials, passed with ``-c`` so git writes nothing.

        ``http.extraHeader`` is used rather than a credential helper because no helper
        configuration is left behind in the checkout, and ``-c`` outranks any config
        file the repository might itself contain.
        """
        token = self._token()
        if not token:
            return []
        header = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        return ["-c", f"http.extraHeader=Authorization: Basic {header}"]

    @staticmethod
    def _validate(repo: str, ref: str) -> None:
        """Both values become a path component *and* a git argument.

        ``repo`` is config- or CLI-supplied and ``ref`` can be a branch name, so neither
        is trusted: a leading ``-`` would be read as an option, and a ``..`` segment would
        walk the checkout root out of its own directory.
        """
        if not valid_repo(repo):
            raise CheckoutError(f"refusing to check out {repo!r}: expected 'owner/name'")
        if not _REF_PATTERN.match(ref) or ".." in ref.split("/"):
            raise CheckoutError(f"refusing to fetch {repo!r} at ref {ref!r}: invalid ref")

    def ensure(self, repo: str, commit_sha: str) -> Checkout:
        """Return a checkout of ``commit_sha``, cloning only if not already cached."""
        self._validate(repo, commit_sha)
        target = self._dir(repo, commit_sha)
        if (target / ".git").is_dir():
            return Checkout(repo=repo, commit_sha=commit_sha, path=target)

        if shutil.which("git") is None:
            raise CheckoutError("git not found on PATH")

        target.parent.mkdir(parents=True, exist_ok=True)
        staging = target.parent / f".{target.name}.partial.{os.getpid()}.{uuid.uuid4().hex[:8]}"
        staging.mkdir(parents=True)
        try:
            _git(["init", "--quiet"], cwd=staging)
            _git(["remote", "add", "origin", self._remote_url(repo)], cwd=staging)
            _git(
                [*self._auth_args(), "fetch", "--quiet", "--depth", "1", "origin", commit_sha],
                cwd=staging,
                secrets=(self._token(),),
            )
            _git(["checkout", "--quiet", "FETCH_HEAD"], cwd=staging)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise

        if target.exists():
            shutil.rmtree(staging, ignore_errors=True)
        else:
            staging.replace(target)
        return Checkout(repo=repo, commit_sha=commit_sha, path=target)

    def evict(self, repo: str, commit_sha: str) -> None:
        shutil.rmtree(self._dir(repo, commit_sha), ignore_errors=True)


def _git(args: list[str], *, cwd: Path, secrets: Iterable[str | None] = ()) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=_CLONE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise CheckoutError(
            f"git {args[0]} timed out after {_CLONE_TIMEOUT_SECONDS}s"
        ) from exc
    if proc.returncode != 0:
        raise CheckoutError(
            f"git {args[0]} failed: {_redact(proc.stderr.strip(), secrets)[:300]}"
        )
    return proc.stdout


def _redact(text: str, secrets: Iterable[str | None]) -> str:
    """Remove every credential value from a message before it is raised or logged.

    Matching a fixed prefix is not enough: git echoes the URL it was given, the header
    it sent, and the credential helper's output, each in a different shape.
    """
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "<redacted>")
    if "x-access-token:" in redacted:
        redacted = "<redacted git error containing credential>"
    return redacted
