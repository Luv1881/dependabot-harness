"""Deterministic helpers shared across stages. No I/O beyond time and randomness."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import random
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any, TypeVar

T = TypeVar("T")


def sha256_hex(*parts: str) -> str:
    """Stable digest over ``|``-joined parts. Order is load-bearing."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def alert_key(
    *, ghsa_id: str, purl: str, resolved_version: str | None, manifest_path: str, repo: str
) -> str:
    """The deduplication anchor (§4). Must stay stable across runs.

    ``manifest_path`` is included so one repo with many manifests produces distinct
    keys (§14.4 monorepo ambiguity).
    """
    return sha256_hex(ghsa_id, purl, resolved_version or "", manifest_path, repo)


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def config_hash(cfg: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(cfg).encode()).hexdigest()


def utcnow() -> str:
    """ISO-8601 UTC, second precision. Every timestamp column uses this."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def age_days(timestamp: str) -> float:
    return (datetime.now(UTC) - parse_ts(timestamp)).total_seconds() / 86400.0


def matches_any(path: str, patterns: Iterable[str]) -> bool:
    """Glob match supporting ``**`` the way the config's invalidation list means it.

    ``**/go.mod`` matches ``go.mod`` at the root as well as nested copies, which plain
    ``fnmatch`` does not do.
    """
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:]):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:].lstrip("/")):
            return True
    return False


class RetryExhausted(RuntimeError):
    """All retry attempts consumed. Carries the last underlying error."""


def retry_with_backoff(
    fn: Callable[[], T],
    *,
    attempts: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    on_retry: Callable[[int, float, BaseException], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> T:
    """Exponential backoff with full jitter.

    Callers persist progress *before* invoking this, so an exhausted retry costs the
    in-flight task and nothing else.
    """
    jitter = rng or random.Random()
    last: BaseException | None = None
    for attempt in range(attempts):
        try:
            return fn()
        except retry_on as exc:
            last = exc
            if attempt == attempts - 1:
                break
            delay = min(base_delay * (2**attempt), max_delay) * jitter.random()
            if on_retry:
                on_retry(attempt + 1, delay, exc)
            sleep(delay)
    raise RetryExhausted(f"exhausted {attempts} attempts") from last


def redact(value: str | None, keep: int = 4) -> str:
    """For log lines only. Secrets never reach the DB at all."""
    if not value:
        return "<unset>"
    return f"<redacted:{len(value)}:{value[:keep]}…>" if len(value) > keep else "<redacted>"
