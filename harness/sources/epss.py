"""EPSS (FIRST) exploit-prediction scores, keyed by CVE."""

from __future__ import annotations

from pathlib import Path

import httpx

from ..util import retry_with_backoff
from ._cache import JsonCache

EPSS_API = "https://api.first.org/data/v1/epss"
_BATCH = 100


class EpssClient:
    def __init__(
        self,
        cache_dir: str | Path,
        *,
        client: httpx.Client | None = None,
        ttl_days: float = 1.0,
    ) -> None:
        self._client = client or httpx.Client(timeout=20.0)
        self._cache = JsonCache(cache_dir, "epss", ttl_days=ttl_days)

    def close(self) -> None:
        self._client.close()

    def score(self, cve_id: str) -> float | None:
        return self.scores([cve_id]).get(cve_id)

    def scores(self, cve_ids: list[str]) -> dict[str, float]:
        """Batched lookup. Absent CVEs are simply missing from the result."""
        wanted = [c for c in dict.fromkeys(cve_ids) if c and c.startswith("CVE-")]
        out: dict[str, float] = {}
        missing: list[str] = []
        for cve in wanted:
            cached = self._cache.get(cve)
            if cached is None:
                missing.append(cve)
            elif cached != {}:
                out[cve] = float(cached)

        for i in range(0, len(missing), _BATCH):
            chunk = missing[i : i + _BATCH]

            def once(chunk: list[str] = chunk) -> httpx.Response:
                return self._client.get(EPSS_API, params={"cve": ",".join(chunk)})

            resp = retry_with_backoff(once, retry_on=(httpx.TransportError,))
            if resp.status_code >= 400:
                continue
            returned = {
                str(row["cve"]): float(row["epss"]) for row in resp.json().get("data") or []
            }
            for cve in chunk:
                if cve in returned:
                    out[cve] = returned[cve]
                    self._cache.put(cve, returned[cve])
                else:
                    self._cache.put(cve, {})
        return out
