"""External data sources. All network I/O lives here."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol, runtime_checkable

from .github import RawAlert


@runtime_checkable
class AlertSource(Protocol):
    """What the ingest stage needs from whatever supplies alerts.

    Dependabot and OSV both satisfy it, so ingest depends on this rather than on either
    concrete client.
    """

    def default_branch_sha(self, repo: str) -> str: ...

    def structure_hash(self, repo: str, sha: str, patterns: tuple[str, ...]) -> str: ...

    def file_text(self, repo: str, path: str, ref: str) -> str | None: ...

    def iter_alerts(self, repo: str) -> Iterator[RawAlert]: ...


@runtime_checkable
class AlertDismisser(Protocol):
    """The one write the emit stage needs. Keeps emit off the full GitHub client."""

    def dismiss_alert(self, repo: str, number: int, *, reason: str, comment: str) -> None: ...


__all__ = ["AlertDismisser", "AlertSource", "RawAlert"]
