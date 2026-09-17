"""Provider model catalogues.

A model id is configuration, and a model id that cannot be checked against the provider
is a guess. Tier names are vendor marketing — "flash", "mini", "turbo" — and the
identifier behind them changes without notice, so an operator should be able to ask the
provider what it actually serves before a run spends money discovering that it does not.

This is a diagnostic. It talks to the provider's listing endpoint directly rather than
through an SDK, so it works for a provider whose SDK is not installed and cannot be
broken by one that is.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx


@dataclass(frozen=True)
class ProviderEndpoint:
    """Where a vendor lists its models, and how it wants to be authenticated."""

    base_url: str
    auth_header: str
    auth_prefix: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)

    def url(self) -> str:
        return f"{self.base_url.rstrip('/')}/models"

    def headers(self, api_key: str) -> dict[str, str]:
        return {
            self.auth_header: f"{self.auth_prefix}{api_key}",
            "Accept": "application/json",
            **self.extra_headers,
        }


ENDPOINTS: dict[str, ProviderEndpoint] = {
    "anthropic": ProviderEndpoint(
        base_url="https://api.anthropic.com/v1",
        auth_header="x-api-key",
        extra_headers={"anthropic-version": "2023-06-01"},
    ),
    "openai": ProviderEndpoint(
        base_url="https://api.openai.com/v1",
        auth_header="Authorization",
        auth_prefix="Bearer ",
    ),
    "deepseek": ProviderEndpoint(
        base_url="https://api.deepseek.com/v1",
        auth_header="Authorization",
        auth_prefix="Bearer ",
    ),
}


class CatalogueError(RuntimeError):
    """The provider's model list could not be read."""


def list_models(
    provider: str,
    api_key: str,
    *,
    client: httpx.Client | None = None,
    timeout: float = 20.0,
) -> list[str]:
    """Model identifiers the given credential can call, sorted.

    Raises rather than returning an empty list: "the provider refused this key" and "this
    key can call nothing" are different answers, and collapsing them would send an
    operator hunting for a model id when the actual problem is a typo in the key.
    """
    endpoint = ENDPOINTS.get(provider)
    if endpoint is None:
        raise CatalogueError(f"no model listing endpoint known for provider {provider!r}")

    owned = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.get(endpoint.url(), headers=endpoint.headers(api_key))
    except httpx.TransportError as exc:
        raise CatalogueError(f"{provider}: cannot reach {endpoint.url()}: {exc}") from exc
    finally:
        if owned:
            http.close()

    if response.status_code == 401:
        raise CatalogueError(f"{provider}: the API key was rejected (401)")
    if response.status_code >= 400:
        raise CatalogueError(f"{provider}: HTTP {response.status_code} from {endpoint.url()}")

    try:
        payload = response.json()
    except ValueError as exc:
        raise CatalogueError(f"{provider}: response was not JSON: {exc}") from exc

    entries = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        raise CatalogueError(f"{provider}: unexpected response shape, no model list found")

    found = {
        str(entry["id"])
        for entry in entries
        if isinstance(entry, dict) and entry.get("id")
    }
    return sorted(found)
