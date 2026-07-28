"""On-disk JSON cache for third-party feeds.

Advisories, EPSS scores, and the KEV feed change slowly. Caching them keeps re-runs
cheap and makes the ingest stage reproducible offline, which the eval harness depends on.
"""

from __future__ import annotations

import hashlib
import json
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
        return self.root / f"{hashlib.sha256(key.encode()).hexdigest()}.json"

    def get(self, key: str) -> Any | None:
        path = self._path(key)
        if not path.is_file():
            return None
        try:
            entry = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        if age_days(entry["fetched_at"]) > self.ttl_days:
            return None
        return entry["value"]

    def put(self, key: str, value: Any) -> None:
        tmp = self._path(key).with_suffix(".tmp")
        tmp.write_text(json.dumps({"fetched_at": utcnow(), "key": key, "value": value}))
        tmp.replace(self._path(key))
