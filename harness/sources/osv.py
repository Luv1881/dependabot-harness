"""OSV.dev advisory enrichment.

The payload that matters is ``affected[].ecosystem_specific.imports`` — the affected
package/symbol list. That list is what makes function-level reachability possible (§5.2).
When it is absent, §14.5 caps reachability at level 2 and confidence at 0.5; callers read
:attr:`Advisory.symbols` being empty as exactly that signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ..util import retry_with_backoff
from ._cache import JsonCache

OSV_API = "https://api.osv.dev/v1"


@dataclass(frozen=True)
class Advisory:
    ghsa_id: str
    summary: str
    details: str
    aliases: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    affected_packages: tuple[str, ...] = ()
    published: str | None = None
    modified: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def symbols_known(self) -> bool:
        return bool(self.symbols)

    @property
    def cve_id(self) -> str | None:
        return next((a for a in self.aliases if a.startswith("CVE-")), None)


class OsvClient:
    def __init__(
        self,
        cache_dir: str | Path,
        *,
        client: httpx.Client | None = None,
        ttl_days: float = 7.0,
    ) -> None:
        self._client = client or httpx.Client(timeout=20.0)
        self._cache = JsonCache(cache_dir, "osv", ttl_days=ttl_days)

    def close(self) -> None:
        self._client.close()

    def fetch(self, vuln_id: str) -> Advisory | None:
        """Fetch by GHSA (or CVE) id. Returns None when OSV has no such record."""
        cached = self._cache.get(vuln_id)
        if cached is not None:
            return _parse(vuln_id, cached) if cached else None

        def once() -> httpx.Response:
            return self._client.get(f"{OSV_API}/vulns/{vuln_id}")

        resp = retry_with_backoff(once, retry_on=(httpx.TransportError,))
        if resp.status_code == 404:
            self._cache.put(vuln_id, {})
            return None
        if resp.status_code >= 400:
            raise RuntimeError(f"OSV {vuln_id}: HTTP {resp.status_code}")
        body = resp.json()
        self._cache.put(vuln_id, body)
        return _parse(vuln_id, body)


def _parse(vuln_id: str, body: dict[str, Any]) -> Advisory:
    symbols: list[str] = []
    packages: list[str] = []
    for affected in body.get("affected") or []:
        pkg = affected.get("package") or {}
        if name := pkg.get("name"):
            packages.append(str(name))
        eco_specific = affected.get("ecosystem_specific") or {}
        for imp in eco_specific.get("imports") or []:
            path = imp.get("path")
            for symbol in imp.get("symbols") or []:
                symbols.append(f"{path}.{symbol}" if path else str(symbol))
            if path and not imp.get("symbols"):
                symbols.append(str(path))
    return Advisory(
        ghsa_id=str(body.get("id") or vuln_id),
        summary=str(body.get("summary") or ""),
        details=str(body.get("details") or ""),
        aliases=tuple(body.get("aliases") or ()),
        symbols=tuple(dict.fromkeys(symbols)),
        affected_packages=tuple(dict.fromkeys(packages)),
        published=body.get("published"),
        modified=body.get("modified"),
        raw=body,
    )
