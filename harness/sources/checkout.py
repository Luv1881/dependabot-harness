"""Read-only, content-addressed repository checkouts.

The spec never says where repo source comes from, but §6 (`not_imported`) and §9
(evidence assembly) both need a working tree. This module is that answer: a shallow
clone per commit SHA, cached, never written to.

The harness has read-only access to source (§17). Nothing here mutates a checkout after
it is created, and callers get the path only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..config import GithubConfig


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

    def _clone_url(self, repo: str) -> str:
        token = self._github.token or os.environ.get("GH_TOKEN")
        if token:
            return f"https://x-access-token:{token}@github.com/{repo}.git"
        return f"https://github.com/{repo}.git"

    def ensure(self, repo: str, commit_sha: str) -> Checkout:
        """Return a checkout of ``commit_sha``, cloning only if not already cached."""
        target = self._dir(repo, commit_sha)
        if (target / ".git").is_dir():
            return Checkout(repo=repo, commit_sha=commit_sha, path=target)

        if shutil.which("git") is None:
            raise CheckoutError("git not found on PATH")

        target.parent.mkdir(parents=True, exist_ok=True)
        staging = target.with_suffix(".partial")
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        try:
            _git(["init", "--quiet"], cwd=staging)
            _git(["remote", "add", "origin", self._clone_url(repo)], cwd=staging)
            _git(["fetch", "--quiet", "--depth", "1", "origin", commit_sha], cwd=staging)
            _git(["checkout", "--quiet", "FETCH_HEAD"], cwd=staging)
        except CheckoutError:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        staging.replace(target)
        return Checkout(repo=repo, commit_sha=commit_sha, path=target)

    def evict(self, repo: str, commit_sha: str) -> None:
        shutil.rmtree(self._dir(repo, commit_sha), ignore_errors=True)


def _git(args: list[str], *, cwd: Path) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if "x-access-token:" in stderr:
            stderr = "<redacted git error containing credential>"
        raise CheckoutError(f"git {args[0]} failed: {stderr[:300]}")
    return proc.stdout
