"""The bounded tool surface available to the judgment agent.

Three read-only tools, a hard call cap, and no shell. Every tool is confined to the
checkout root; a path that escapes it is refused rather than resolved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..sources.osv import OsvClient

MAX_READ_LINES = 200
MAX_GREP_MATCHES = 40
MAX_GREP_FILES = 2000
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

        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(arguments.get("start") or 1))
        end = int(arguments.get("end") or start + MAX_READ_LINES - 1)
        end = min(len(lines), end, start + MAX_READ_LINES - 1)
        if start > len(lines):
            return f"error: file has {len(lines)} lines; start {start} is past the end"
        body = "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))
        return f"{arguments.get('path')} lines {start}-{end}:\n{body}"

    def _grep(self, arguments: dict[str, Any]) -> str:
        if self.repo_root is None:
            return "error: no checkout available"
        try:
            pattern = re.compile(str(arguments.get("pattern", "")))
        except re.error as exc:
            return f"error: invalid regular expression: {exc}"

        glob = str(arguments.get("glob") or "*")
        matches: list[str] = []
        scanned = 0
        for path in sorted(self.repo_root.rglob(glob)):
            if scanned >= MAX_GREP_FILES or len(matches) >= MAX_GREP_MATCHES:
                break
            if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
                continue
            scanned += 1
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            relative = path.relative_to(self.repo_root)
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
        advisory = self.osv.fetch(str(arguments.get("id", "")))
        if advisory is None:
            return f"no advisory found for {arguments.get('id')}"
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
