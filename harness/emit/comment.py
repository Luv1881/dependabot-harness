"""PR comment rendering.

Shows only the diff of verdicts against the base branch. Re-dumping the full set on every
push trains reviewers to skip the comment, which defeats the point of writing one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_ORDER = {"affected": 0, "could_not_determine": 1, "not_affected": 2, "fixed": 3}
_ICON = {
    "affected": "reachable",
    "could_not_determine": "undetermined",
    "not_affected": "not affected",
    "fixed": "already fixed",
}


@dataclass
class VerdictDiff:
    added: list[dict[str, Any]] = field(default_factory=list)
    changed: list[tuple[dict[str, Any], dict[str, Any]]] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.changed or self.resolved)


def diff_verdicts(base: dict[str, dict[str, Any]], head: dict[str, dict[str, Any]]) -> VerdictDiff:
    """Compare two alert_key -> verdict maps."""
    diff = VerdictDiff()
    for key, verdict in head.items():
        previous = base.get(key)
        if previous is None:
            diff.added.append(verdict)
        elif previous.get("verdict") != verdict.get("verdict"):
            diff.changed.append((previous, verdict))
    for key, verdict in base.items():
        if key not in head:
            diff.resolved.append(verdict)
    return diff


def render(diff: VerdictDiff, *, repo: str) -> str:
    if diff.is_empty:
        return f"**Dependency triage** — no verdict changes in `{repo}`."

    lines = [f"**Dependency triage** — verdict changes in `{repo}`", ""]

    if diff.added:
        lines.append(f"### New ({len(diff.added)})")
        lines.extend(_row(v) for v in sorted(diff.added, key=_sort_key))
        lines.append("")

    if diff.changed:
        lines.append(f"### Changed ({len(diff.changed)})")
        for previous, current in sorted(diff.changed, key=lambda pair: _sort_key(pair[1])):
            was = _ICON.get(str(previous.get("verdict")), "unknown")
            lines.append(f"{_row(current)} (was: {was})")
        lines.append("")

    if diff.resolved:
        lines.append(f"### No longer present ({len(diff.resolved)})")
        lines.extend(
            f"- `{v.get('purl', 'unknown')}` — {v.get('ghsa_id', '')}" for v in diff.resolved
        )
        lines.append("")

    needs_human = [v for v in diff.added if v.get("needs_human")]
    if needs_human:
        lines.append(f"{len(needs_human)} verdict(s) need human review before this merges.")

    return "\n".join(lines).rstrip()


def _row(verdict: dict[str, Any]) -> str:
    label = _ICON.get(str(verdict.get("verdict")), "unknown")
    purl = verdict.get("purl", "unknown")
    ghsa = verdict.get("ghsa_id", "")
    confidence = verdict.get("confidence")
    is_number = isinstance(confidence, int | float) and not isinstance(confidence, bool)
    suffix = f" ({confidence:.0%} confidence)" if is_number else ""
    action = verdict.get("recommended_action")
    tail = f" — {action}" if action and verdict.get("verdict") == "affected" else ""
    return f"- **{label}** `{purl}` {ghsa}{suffix}{tail}"


def _sort_key(verdict: dict[str, Any]) -> tuple[int, str]:
    return (_ORDER.get(str(verdict.get("verdict")), 9), str(verdict.get("purl", "")))
