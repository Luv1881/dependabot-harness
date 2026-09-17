"""Scanning a working tree that is already on disk.

``scan-public`` fetches a repository from GitHub, which needs a credential and a network.
Neither is always available or appropriate: a private mirror, an air-gapped CI runner, a
reviewer checking a colleague's branch, and the harness's own end-to-end tests all have
the code locally already and no reason to make three API calls to obtain it.

This supplies the same :class:`~harness.sources.AlertSource` surface backed by a
directory, so every stage downstream is unchanged and unaware of the difference. The only
things a local tree cannot answer are the ones that are properties of a *hosted*
repository — there is no default branch and no server-side object database — so those are
derived from the tree itself, deterministically.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..fsutil import DEFAULT_SKIP_DIRS, iter_repo_files
from ..util import matches_any, sha256_hex
from .checkout import Checkout, CheckoutError

_LOCAL_SHA = re.compile(r"^[0-9a-f]{7,64}$")

_MAX_FILE_BYTES = 4_000_000
"""Matches the manifest ceiling the discovery pass uses, so the two agree on what counts
as readable rather than one silently accepting what the other skips."""


@dataclass(frozen=True)
class LocalRepo:
    """A checkout-shaped host backed by a directory.

    Satisfies the pieces of the alert-source protocol that describe *the tree*:
    ``structure_hash`` and ``file_text``. It deliberately does not implement
    ``iter_alerts`` — that comes from :class:`~harness.sources.osv_scan.OsvAlertSource`,
    which is wrapped around this.
    """

    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root).resolve())

    def close(self) -> None:
        """Nothing to release: the tree belongs to the caller and is never written to."""

    def default_branch_sha(self, repo: str) -> str:
        """The commit to analyse: whatever this tree is checked out at.

        Named for the protocol member it satisfies, because it answers the same question
        — *which revision of this code are we reasoning about?* — even though a directory
        has no branches. A local run is still recorded in ``repo_snapshots`` and still
        pins its verdicts to a structure hash, so cache invalidation behaves identically.

        A directory export that is not a git tree falls back to a content digest rather
        than to a placeholder, so it is still distinguishable from a different revision.
        """
        sha = self._git(["rev-parse", "HEAD"])
        if sha and _LOCAL_SHA.match(sha):
            return sha
        return sha256_hex(*self._manifest_digest())[:40]

    def _git(self, args: list[str]) -> str | None:
        try:
            proc = subprocess.run(
                ["git", *args],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return proc.stdout.strip() if proc.returncode == 0 else None

    def _manifest_digest(self) -> list[str]:
        return [
            f"{path.relative_to(self.root)}:{path.stat().st_size}"
            for path in iter_repo_files(self.root, skip_dirs=DEFAULT_SKIP_DIRS)
        ]

    def structure_hash(self, repo: str, sha: str, patterns: tuple[str, ...]) -> str:
        """Digest of every watched path's contents, by relative path.

        Same contract as the API-backed version: it changes exactly when a watched file's
        content or set membership changes, and not on an unrelated commit. The remote
        version hashes blob OIDs from the server; this hashes the bytes, because there is
        no object database to ask.
        """
        entries: list[str] = []
        for path in sorted(iter_repo_files(self.root, skip_dirs=DEFAULT_SKIP_DIRS)):
            relative = str(path.relative_to(self.root))
            if not matches_any(relative, patterns):
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    entries.append(f"{relative}:oversized")
                    continue
                digest = sha256_hex(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                entries.append(f"{relative}:unreadable")
                continue
            entries.append(f"{relative}:{digest}")
        return sha256_hex(*entries)

    def file_text(self, repo: str, path: str, ref: str) -> str | None:
        """Read one repository-relative file. Returns None for a missing path."""
        target = self._resolve(path)
        if target is None or not target.is_file():
            return None
        try:
            if target.stat().st_size > _MAX_FILE_BYTES:
                return None
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def _resolve(self, relative: str) -> Path | None:
        if not relative or relative.startswith("/") or "\\" in relative:
            return None
        if ".." in relative.split("/"):
            return None
        try:
            resolved = (self.root / relative).resolve()
        except OSError:
            return None
        return resolved if resolved.is_relative_to(self.root) else None


@dataclass(frozen=True)
class LocalCheckout:
    """A checkout manager that returns the path it was handed.

    Stages ask for a checkout of ``(repo, sha)``. For a local scan the working tree *is*
    the checkout, so nothing is fetched and nothing is copied — and in particular the
    caller's directory is never written to.
    """

    root: Path

    def ensure(self, repo: str, commit_sha: str) -> Checkout:
        if not self.root.is_dir():
            raise CheckoutError(f"local checkout is not a directory: {self.root}")
        return Checkout(repo=repo, commit_sha=commit_sha, path=self.root)

    def evict(self, repo: str, commit_sha: str) -> None:
        """Refuses. Eviction here would delete the operator's working tree."""
        raise CheckoutError("refusing to evict a local checkout; it is not ours to delete")


def local_repo_label(root: Path) -> str:
    """A stable ``owner/name``-shaped label for a directory.

    Downstream stages key on the repo string — it is part of ``alert_key`` and it becomes
    a directory name in the emit stage — so it has to be slugged rather than used raw. The
    label is derived from the path so two different trees cannot collide in one database.
    """
    resolved = Path(root).resolve()
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", resolved.name).strip("-") or "tree"
    return f"local/{slug}-{sha256_hex(str(resolved))[:8]}"
