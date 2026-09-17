"""On-disk JSON cache for third-party feeds.

Advisories, EPSS scores, and the KEV feed change slowly. Caching them keeps re-runs
cheap and makes the ingest stage reproducible offline, which the eval harness depends on.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from ..util import age_days, utcnow


class JsonCache:
    """Content-addressed JSON cache with a per-entry TTL."""

    def __init__(self, root: str | Path, namespace: str, ttl_days: float = 7.0) -> None:
        self.root = Path(root) / namespace
        self.root.mkdir(parents=True, exist_ok=True)
        self.ttl_days = ttl_days

    def _path(self, key: str) -> Path:
        """Keys are hashed, never used as filenames.

        A cache key can be a model-supplied advisory id, so a traversal sequence in one
        must not be able to choose where the write lands.
        """
        return self.root / f"{hashlib.sha256(key.encode()).hexdigest()}.json"

    def get(self, key: str) -> Any | None:
        """The cached value, or None when absent, expired, or unreadable.

        A malformed entry is a miss rather than an exception. A truncated cache file is
        not a reason to abort a triage run, and refusing to start because of one would
        turn a local disk problem into a fleet-wide outage.
        """
        path = self._path(key)
        if not path.is_file():
            return None
        try:
            entry = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            return None
        if not isinstance(entry, dict):
            return None
        fetched_at = entry.get("fetched_at")
        if not isinstance(fetched_at, str):
            return None
        try:
            expired = age_days(fetched_at) > self.ttl_days
        except (TypeError, ValueError):
            return None
        if expired:
            return None
        return entry.get("value")

    def put(self, key: str, value: Any) -> None:
        path = self._path(key)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"fetched_at": utcnow(), "key": key, "value": value}))
        tmp.replace(path)
