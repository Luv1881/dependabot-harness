"""The `harness models` diagnostic.

Tier names are vendor marketing; the identifier is what the API accepts. This asks the
provider directly, so a config is not written on a guess and a run does not spend money
discovering that the guess was wrong.
"""

from __future__ import annotations

import httpx
import pytest

from harness.models.catalogue import ENDPOINTS, CatalogueError, list_models


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: object = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> object:
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeHttp:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests: list[tuple[str, dict[str, str]]] = []
        self.closed = False

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append((url, dict(kwargs.get("headers") or {})))  # type: ignore[arg-type]
        return self.response

    def close(self) -> None:
        self.closed = True


def http_ok(ids: list[str]) -> FakeHttp:
    return FakeHttp(FakeResponse(payload={"object": "list", "data": [{"id": i} for i in ids]}))


class TestListing:
    def test_model_ids_are_returned_sorted(self) -> None:
        http = http_ok(["deepseek-reasoner", "deepseek-chat"])
        assert list_models("deepseek", "sk-test", client=http) == [  # type: ignore[arg-type]
            "deepseek-chat",
            "deepseek-reasoner",
        ]

    def test_a_bare_list_is_also_accepted(self) -> None:
        http = FakeHttp(FakeResponse(payload=[{"id": "m1"}, {"id": "m2"}]))
        assert list_models("deepseek", "k", client=http) == ["m1", "m2"]  # type: ignore[arg-type]

    def test_entries_without_an_id_are_ignored(self) -> None:
        http = FakeHttp(FakeResponse(payload={"data": [{"id": "m1"}, {"object": "model"}, "junk"]}))
        assert list_models("deepseek", "k", client=http) == ["m1"]  # type: ignore[arg-type]

    def test_an_empty_catalogue_is_an_empty_list_not_an_error(self) -> None:
        http = FakeHttp(FakeResponse(payload={"data": []}))
        assert list_models("deepseek", "k", client=http) == []  # type: ignore[arg-type]


class TestAuthentication:
    def test_deepseek_sends_a_bearer_header(self) -> None:
        http = http_ok(["deepseek-chat"])
        list_models("deepseek", "sk-secret", client=http)  # type: ignore[arg-type]
        url, headers = http.requests[0]
        assert url == "https://api.deepseek.com/v1/models"
        assert headers["Authorization"] == "Bearer sk-secret"

    def test_anthropic_sends_its_own_header_shape(self) -> None:
        http = http_ok(["claude-opus-5"])
        list_models("anthropic", "sk-ant-secret", client=http)  # type: ignore[arg-type]
        _, headers = http.requests[0]
        assert headers["x-api-key"] == "sk-ant-secret"
        assert headers["anthropic-version"] == "2023-06-01"
        assert "Authorization" not in headers

    def test_only_an_api_key_goes_into_a_header(self) -> None:
        """No GitHub token or other ambient credential may leak into this request."""
        http = http_ok(["deepseek-chat"])
        list_models("deepseek", "sk-secret", client=http)  # type: ignore[arg-type]
        _, headers = http.requests[0]
        assert set(headers) == {"Authorization", "Accept"}


class TestFailuresAreDistinct:
    """'The provider refused this key' and 'this key can call nothing' are different
    answers. Collapsing them sends an operator hunting for a model id when the problem is
    a typo in the key."""

    def test_a_rejected_key_names_the_problem(self) -> None:
        http = FakeHttp(FakeResponse(status_code=401, text="unauthorized"))
        with pytest.raises(CatalogueError, match="rejected \\(401\\)"):
            list_models("deepseek", "bad", client=http)  # type: ignore[arg-type]

    def test_an_http_error_reports_the_status(self) -> None:
        http = FakeHttp(FakeResponse(status_code=503))
        with pytest.raises(CatalogueError, match="HTTP 503"):
            list_models("deepseek", "k", client=http)  # type: ignore[arg-type]

    def test_a_transport_failure_is_reported_not_swallowed(self) -> None:
        class Unreachable(FakeHttp):
            def get(self, url: str, **kwargs: object) -> FakeResponse:
                raise httpx.ConnectError("dns failure")

        with pytest.raises(CatalogueError, match="cannot reach"):
            list_models("deepseek", "k", client=Unreachable(FakeResponse()))  # type: ignore[arg-type]

    def test_a_non_json_body_is_reported(self) -> None:
        http = FakeHttp(FakeResponse(payload=None))
        with pytest.raises(CatalogueError, match="not JSON"):
            list_models("deepseek", "k", client=http)  # type: ignore[arg-type]

    def test_an_unexpected_shape_is_reported(self) -> None:
        http = FakeHttp(FakeResponse(payload={"models": []}))
        with pytest.raises(CatalogueError, match="unexpected response shape"):
            list_models("deepseek", "k", client=http)  # type: ignore[arg-type]

    def test_an_unknown_provider_is_reported_rather_than_guessed(self) -> None:
        with pytest.raises(CatalogueError, match="no model listing endpoint"):
            list_models("bedrock", "k")


class TestEndpoints:
    def test_every_registered_provider_has_an_endpoint(self) -> None:
        from harness.models.client import PROVIDER_API_KEY_ENV

        assert set(ENDPOINTS) == set(PROVIDER_API_KEY_ENV)

    def test_every_endpoint_is_https(self) -> None:
        for provider, endpoint in ENDPOINTS.items():
            assert endpoint.base_url.startswith("https://"), provider

    def test_the_url_appends_models_to_the_versioned_base(self) -> None:
        assert ENDPOINTS["deepseek"].url() == "https://api.deepseek.com/v1/models"
        assert ENDPOINTS["openai"].url() == "https://api.openai.com/v1/models"

    def test_a_client_owned_by_the_caller_is_not_closed(self) -> None:
        http = http_ok(["m"])
        list_models("deepseek", "k", client=http)  # type: ignore[arg-type]
        assert http.closed is False
