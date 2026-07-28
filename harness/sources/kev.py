"""CISA Known Exploited Vulnerabilities catalog membership."""

from __future__ import annotations

from pathlib import Path

import httpx

from ..util import retry_with_backoff
from ._cache import JsonCache

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEY = "catalog"


class KevClient:
    def __init__(
        self,
        cache_dir: str | Path,
        *,
        client: httpx.Client | None = None,
        ttl_days: float = 1.0,
    ) -> None:
        self._client = client or httpx.Client(timeout=30.0)
        self._cache = JsonCache(cache_dir, "kev", ttl_days=ttl_days)
        self._members: frozenset[str] | None = None

    def close(self) -> None:
        self._client.close()

    def _load(self) -> frozenset[str]:
        if self._members is not None:
            return self._members
        cached = self._cache.get(_KEY)
        if cached is None:

            def once() -> httpx.Response:
                return self._client.get(KEV_FEED)

            resp = retry_with_backoff(once, retry_on=(httpx.TransportError,))
            if resp.status_code >= 400:
                raise RuntimeError(f"KEV feed: HTTP {resp.status_code}")
            cached = [str(v["cveID"]) for v in resp.json().get("vulnerabilities") or []]
            self._cache.put(_KEY, cached)
        self._members = frozenset(cached)
        return self._members

    def contains(self, cve_id: str | None) -> bool:
        """False for a missing CVE id — absence from KEV is not a claim of safety, but
        membership genuinely requires a CVE to look up."""
        if not cve_id:
            return False
        return cve_id in self._load()
