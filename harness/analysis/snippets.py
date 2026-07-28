"""Bounded source windows around a call site.

Snippets are extracted windows, never whole files: the judgment agent must receive a
deterministically assembled context, not an invitation to read the repository.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_RADIUS = 20
_MAX_SNIPPET_BYTES = 8_000


@dataclass(frozen=True)
class Snippet:
    text: str
    start_line: int
    end_line: int
    truncated: bool = False

    @classmethod
    def empty(cls) -> Snippet:
        return cls(text="", start_line=0, end_line=0)


def extract(
    repo_root: Path, relative_path: str, line: int, radius: int = DEFAULT_RADIUS
) -> Snippet:
    """Window of +/- ``radius`` lines around ``line``, 1-indexed and clamped to the file."""
    if line < 1:
        return Snippet.empty()
    target = _safe_join(repo_root, relative_path)
    if target is None or not target.is_file():
        return Snippet.empty()
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return Snippet.empty()
    if not lines:
        return Snippet.empty()

    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    body = "\n".join(lines[start - 1 : end])
    truncated = False
    if len(body.encode()) > _MAX_SNIPPET_BYTES:
        body = body.encode()[:_MAX_SNIPPET_BYTES].decode(errors="ignore")
        truncated = True
    return Snippet(text=body, start_line=start, end_line=end, truncated=truncated)


def _safe_join(root: Path, relative: str) -> Path | None:
    """Resolve ``relative`` under ``root``, refusing anything that escapes the checkout."""
    try:
        resolved = (root / relative).resolve()
        root_resolved = root.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(root_resolved):
        return None
    return resolved


def to_relative(repo_root: Path, absolute_or_relative: str) -> str:
    """Best-effort repo-relative path for a tool-reported location."""
    candidate = Path(absolute_or_relative)
    if not candidate.is_absolute():
        return absolute_or_relative
    try:
        return str(candidate.resolve().relative_to(repo_root.resolve()))
    except (ValueError, OSError):
        return absolute_or_relative
