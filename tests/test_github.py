"""GitHub request-target hardening.

`file_text` interpolates a caller-supplied path into a request URL that carries the
operator's installation token. A `..` segment or a query character retargets that
request, so the path is validated and percent-encoded before it is used.
"""

from __future__ import annotations

import base64

import pytest

from harness.config import GithubConfig
from harness.sources.github import GithubClient, GithubError


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: object = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> object:
        return self._payload


class FakeHttp:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests: list[tuple[str, str, dict[str, object]]] = []

    def request(self, method: str, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append((method, url, kwargs))
        return self.response

    def close(self) -> None:
        pass


def client(response: FakeResponse) -> tuple[GithubClient, FakeHttp]:
    http = FakeHttp(response)
    cfg = GithubConfig(org="o", repos=("o/r",), token="ghp_test")
    return GithubClient(cfg, client=http), http  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "path",
    [
        "../secrets",
        "a/../../b",
        "../../../user/repos",
        "/etc/passwd",
        "a\\..\\b",
        "",
    ],
)
def test_a_path_that_escapes_the_repository_is_refused_before_any_request(path: str) -> None:
    gh, http = client(FakeResponse())
    with pytest.raises(GithubError, match="refusing path"):
        gh.file_text("o/r", path, "sha")
    assert http.requests == []


@pytest.mark.parametrize(
    "path",
    ["go.mod", "services/api/package.json", "a/b/c/requirements.txt", "my manifest.json"],
)
def test_an_ordinary_manifest_path_is_url_encoded(path: str) -> None:
    payload = {"encoding": "base64", "content": base64.b64encode(b"hello").decode()}
    gh, http = client(FakeResponse(payload=payload))

    assert gh.file_text("o/r", path, "sha") == "hello"

    method, url, kwargs = http.requests[0]
    assert method == "GET"
    assert " " not in url
    assert url.endswith("/contents/" + path.replace(" ", "%20"))
    assert kwargs["params"] == {"ref": "sha"}


def test_a_dotfile_is_not_mistaken_for_traversal() -> None:
    payload = {"encoding": "base64", "content": base64.b64encode(b"x").decode()}
    gh, _ = client(FakeResponse(payload=payload))
    assert gh.file_text("o/r", ".github/dependabot.yml", "sha") == "x"


def test_a_missing_path_returns_none_rather_than_raising() -> None:
    gh, _ = client(FakeResponse(status_code=404))
    assert gh.file_text("o/r", "go.mod", "sha") is None


def test_a_non_base64_encoding_returns_none() -> None:
    gh, _ = client(FakeResponse(payload={"encoding": "none"}))
    assert gh.file_text("o/r", "big.bin", "sha") is None
