"""Filesystem primitives for walking a checkout.

A checkout is untrusted input. It is a working tree produced from a repository the
operator does not control, and git faithfully materialises whatever symlinks that
repository contains. ``Path.rglob`` follows a symlinked directory, so a repository
holding ``loop -> .`` can make a naive walk either leave the tree or never terminate.

:func:`iter_repo_files` is the single answer to that, used by every stage that reads a
working tree, so the guarantee is stated once rather than re-derived per caller.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "target",
        "testdata",
        "vendor",
        "venv",
    }
)
"""Directories never worth walking: vendored copies, build output, and VCS internals."""

MAX_DEPTH = 64
"""A directory tree deeper than this is malformed, not deep. Bounds the recursion so a
hostile checkout cannot exhaust the interpreter's stack while being walked."""


def iter_repo_files(
    root: Path,
    *,
    skip_dirs: frozenset[str] | None = None,
    suffixes: tuple[str, ...] = (),
) -> Iterator[Path]:
    """Regular files under ``root``, confined to ``root``, in lexicographic order.

    Four properties the callers depend on:

    - **Directory symlinks are never descended into.** A repository holding ``loop -> .``
      would otherwise make the walk leave the tree or never terminate.
    - **Every yielded file resolves inside ``root``.** A symlinked *file* pointed at
      ``/etc/passwd`` is still a file, and ``read_text`` would happily follow it. Callers
      that read what they are given therefore need no separate check.
    - **Skipped directories are pruned**, so a nested ``node_modules`` is never entered
      and the walk does not pay for files it is about to discard.
    - **Order is total and reproducible.** Entries are visited sorted and directories are
      recursed into in place, so the yielded sequence equals the sorted sequence of
      relative paths. Deterministic context assembly depends on this.

    The walk is lazy: only one directory's entries exist in memory at a time.
    """
    if not root.is_dir():
        return
    resolved_root = _resolve(root)
    if resolved_root is None:
        return
    skip = DEFAULT_SKIP_DIRS if skip_dirs is None else skip_dirs
    yield from _walk(root, skip, suffixes, resolved_root, depth=0)


def _walk(
    directory: Path,
    skip: frozenset[str],
    suffixes: tuple[str, ...],
    resolved_root: Path,
    *,
    depth: int,
) -> Iterator[Path]:
    if depth > MAX_DEPTH:
        return
    try:
        entries = sorted(directory.iterdir(), key=lambda entry: entry.name)
    except OSError:
        return

    for entry in entries:
        is_directory = _is_dir(entry)
        if is_directory and entry.is_symlink():
            continue
        if is_directory:
            if entry.name in skip:
                continue
            yield from _walk(entry, skip, suffixes, resolved_root, depth=depth + 1)
            continue
        if suffixes and not entry.name.endswith(suffixes):
            continue
        resolved = _resolve(entry)
        if resolved is None or not resolved.is_relative_to(resolved_root):
            continue
        yield entry


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _resolve(path: Path) -> Path | None:
    try:
        return path.resolve()
    except OSError:
        return None
