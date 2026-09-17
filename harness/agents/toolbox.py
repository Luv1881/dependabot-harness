"""The bounded tool surface available to the judgment agent.

Three read-only tools, a hard call cap, and no shell. Every tool is confined to the
checkout root; a path that escapes it is refused rather than resolved.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..fsutil import iter_repo_files
from ..sources.osv import OsvClient

MAX_READ_LINES = 200
MAX_GREP_MATCHES = 40
MAX_GREP_FILES = 2000
MAX_FILE_BYTES = 2_000_000
"""Largest file any tool will load. A checkout is untrusted input, and a hostile repo
can contain a multi-gigabyte file purely to exhaust memory before a single line is read."""

MAX_GREP_BYTES = 8_000_000
"""Total bytes one grep call may load across every file it visits."""

_ADVISORY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SKIP_DIRS = frozenset({".git", "node_modules", "vendor", "target", "dist", ".venv"})


class ToolCallCapReached(RuntimeError):
    """The agent exhausted its tool budget and must answer could_not_determine."""


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": (
            "Read a bounded window of a file in the repository under analysis. "
            "Returns numbered lines so they can be cited."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repository-relative file path"},
                "start": {"type": "integer", "description": "First line, 1-indexed"},
                "end": {"type": "integer", "description": "Last line, inclusive"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "grep",
        "description": "Search the repository for a regular expression. Returns file:line matches.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "glob": {"type": "string", "description": "Optional filename glob filter"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "fetch_advisory",
        "description": "Fetch an advisory by GHSA or CVE id.",
        "input_schema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
]


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    result: str
    error: str | None = None


@dataclass
class Toolbox:
    """Stateful across one alert: counts calls and records them for the audit trail."""

    repo_root: Path | None
    osv: OsvClient | None = None
    max_calls: int = 8
    calls: list[ToolCall] = field(default_factory=list)

    @property
    def used(self) -> int:
        return len(self.calls)

    @property
    def remaining(self) -> int:
        return max(0, self.max_calls - self.used)

    @property
    def exhausted(self) -> bool:
        return self.remaining == 0

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        if self.exhausted:
            raise ToolCallCapReached(f"tool call cap of {self.max_calls} reached")
        handler = {
            "read_file": self._read_file,
            "grep": self._grep,
            "fetch_advisory": self._fetch_advisory,
        }.get(name)
        if handler is None:
            result = f"error: unknown tool {name!r}"
            self.calls.append(ToolCall(name, arguments, result, error="unknown tool"))
            return result
        try:
            result = handler(arguments)
            self.calls.append(ToolCall(name, arguments, result))
        except Exception as exc:
            result = f"error: {type(exc).__name__}: {exc}"
            self.calls.append(ToolCall(name, arguments, result, error=str(exc)))
        return result

    def _read_file(self, arguments: dict[str, Any]) -> str:
        if self.repo_root is None:
            return "error: no checkout available"
        target = self._resolve(str(arguments.get("path", "")))
        if target is None:
            return "error: path is outside the repository"
        if not target.is_file():
            return f"error: no such file: {arguments.get('path')}"
        try:
            size = target.stat().st_size
        except OSError as exc:
            return f"error: cannot stat {arguments.get('path')}: {exc}"
        if size > MAX_FILE_BYTES:
            return (
                f"error: {arguments.get('path')} is {size} bytes, above the "
                f"{MAX_FILE_BYTES}-byte read limit"
            )

        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(arguments.get("start") or 1))
        end = int(arguments.get("end") or start + MAX_READ_LINES - 1)
        end = min(len(lines), end, start + MAX_READ_LINES - 1)
        if start > len(lines):
            return f"error: file has {len(lines)} lines; start {start} is past the end"
        body = "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))
        return f"{arguments.get('path')} lines {start}-{end}:\n{body}"

    def _grep(self, arguments: dict[str, Any]) -> str:
        """Search the checkout, never outside it.

        The glob is model-controlled and the model reads an untrusted repository, so the
        walk is confined by construction: the directory walk does not follow symlinks and
        every candidate file is resolved and re-checked against the checkout root before
        it is opened. A pattern that tries to climb out with ``..`` is refused outright
        rather than normalised, because normalising it is what would make it work.
        """
        if self.repo_root is None:
            return "error: no checkout available"
        try:
            pattern = re.compile(str(arguments.get("pattern", "")))
        except re.error as exc:
            return f"error: invalid regular expression: {exc}"

        glob = str(arguments.get("glob") or "*")
        if _escapes(glob):
            return "error: glob must stay within the repository"

        matches: list[str] = []
        scanned = 0
        budget = MAX_GREP_BYTES
        for path in iter_repo_files(self.repo_root, skip_dirs=_SKIP_DIRS):
            if scanned >= MAX_GREP_FILES or len(matches) >= MAX_GREP_MATCHES or budget <= 0:
                break
            relative = path.relative_to(self.repo_root)
            if not _matches_glob(str(relative), glob):
                continue
            if self._resolve(str(relative)) is None:
                continue
            scanned += 1
            try:
                size = path.stat().st_size
                if size > MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            budget -= size
            for number, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    matches.append(f"{relative}:{number}: {line.strip()[:200]}")
                    if len(matches) >= MAX_GREP_MATCHES:
                        break
        if not matches:
            return "no matches"
        return "\n".join(matches)

    def _fetch_advisory(self, arguments: dict[str, Any]) -> str:
        if self.osv is None:
            return "error: advisory lookup unavailable"
        vuln_id = str(arguments.get("id", "")).strip()
        if not _ADVISORY_ID.match(vuln_id):
            return "error: advisory id must be a bare identifier such as GHSA-xxxx-yyyy-zzzz"
        advisory = self.osv.fetch(vuln_id)
        if advisory is None:
            return f"no advisory found for {vuln_id}"
        return (
            f"{advisory.ghsa_id}: {advisory.summary}\n"
            f"aliases: {', '.join(advisory.aliases) or 'none'}\n"
            f"affected symbols: {', '.join(advisory.symbols) or 'none recorded'}\n\n"
            f"{advisory.details[:2000]}"
        )

    def _resolve(self, relative: str) -> Path | None:
        if self.repo_root is None:
            return None
        try:
            resolved = (self.repo_root / relative).resolve()
            root = self.repo_root.resolve()
        except OSError:
            return None
        return resolved if resolved.is_relative_to(root) else None

    def audit(self) -> list[dict[str, Any]]:
        return [{"tool": c.name, "arguments": c.arguments, "error": c.error} for c in self.calls]


def _escapes(glob: str) -> bool:
    """Whether a glob tries to leave the repository."""
    text = glob.strip()
    if not text or text.startswith("~") or Path(text).is_absolute():
        return True
    return ".." in Path(text).parts


def _matches_glob(relative: str, glob: str) -> bool:
    """Glob semantics that match ``Path.rglob``: a bare pattern matches at any depth."""
    return fnmatch.fnmatch(relative, glob) or fnmatch.fnmatch(relative, f"**/{glob}")
