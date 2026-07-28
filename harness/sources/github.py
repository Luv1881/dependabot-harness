"""GitHub client: Dependabot alerts (GraphQL), git trees, manifest fetch, dismissal.

GraphQL is used for alerts rather than REST — REST paginates poorly at fleet scale (§5).

``structure_hash`` is computed here from git-tree blob OIDs, not from a clone: it must be
available at ingest time, before any agent stage has run (see CLAUDE.md resolution 1).
"""

from __future__ import annotations

import base64
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from ..config import GithubConfig
from ..util import matches_any, retry_with_backoff, sha256_hex

API = "https://api.github.com"
GRAPHQL = f"{API}/graphql"

_ALERTS_QUERY = """
query($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    defaultBranchRef { target { oid } }
    vulnerabilityAlerts(first: 100, after: $cursor, states: [OPEN, FIXED, DISMISSED]) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        state
        createdAt
        vulnerableManifestPath
        vulnerableRequirements
        dependencyScope
        securityVulnerability {
          severity
          package { name ecosystem }
          firstPatchedVersion { identifier }
          vulnerableVersionRange
          advisory {
            ghsaId
            summary
            cvss { score vectorString }
            identifiers { type value }
          }
        }
      }
    }
  }
}
"""


class GithubError(RuntimeError):
    """Non-retryable GitHub API failure, or a GraphQL `errors` payload."""


class GithubRateLimited(RuntimeError):
    """Retryable: secondary rate limit or 403/429 with a reset hint."""


@dataclass(frozen=True)
class RawAlert:
    """One Dependabot alert as GitHub reports it, before enrichment."""

    repo: str
    number: int
    state: str
    created_at: str
    manifest_path: str
    requirements: str | None
    scope_hint: str | None
    ghsa_id: str
    cve_id: str | None
    package_name: str
    ecosystem: str
    patched_version: str | None
    vulnerable_range: str | None
    severity: str | None
    cvss_score: float | None
    cvss_vector: str | None
    summary: str


class GithubClient:
    """Read-only except for the explicitly-write methods at the bottom."""

    def __init__(self, cfg: GithubConfig, *, client: httpx.Client | None = None) -> None:
        self.cfg = cfg
        self._client = client or httpx.Client(timeout=30.0)
        self._token: str | None = None
        self._token_expiry: float = 0.0

    def close(self) -> None:
        self._client.close()

    def _installation_token(self) -> str:
        """Mint a short-lived installation token from the App private key."""
        import jwt

        assert self.cfg.private_key_path is not None
        key = Path(self.cfg.private_key_path).read_text()
        now = int(time.time())
        assertion = jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": self.cfg.app_id},
            key,
            algorithm="RS256",
        )
        resp = self._client.post(
            f"{API}/app/installations/{self.cfg.installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {assertion}",
                "Accept": "application/vnd.github+json",
            },
        )
        if resp.status_code >= 400:
            raise GithubError(f"installation token request failed: {resp.status_code}")
        return str(resp.json()["token"])

    def _auth_header(self) -> str:
        if not self.cfg.uses_app_auth:
            assert self.cfg.token is not None
            return f"Bearer {self.cfg.token}"
        if self._token is None or time.time() > self._token_expiry:
            self._token = self._installation_token()
            self._token_expiry = time.time() + 3000
        return f"Bearer {self._token}"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._auth_header(),
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        def once() -> httpx.Response:
            resp = self._client.request(method, url, headers=self._headers(), **kwargs)
            if resp.status_code in (403, 429) and "rate limit" in resp.text.lower():
                raise GithubRateLimited(f"{resp.status_code} on {url}")
            if resp.status_code >= 500:
                raise GithubRateLimited(f"{resp.status_code} on {url}")
            return resp

        return retry_with_backoff(once, retry_on=(GithubRateLimited, httpx.TransportError))

    def _graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        resp = self._request("POST", GRAPHQL, json={"query": query, "variables": variables})
        if resp.status_code >= 400:
            raise GithubError(f"graphql {resp.status_code}: {resp.text[:200]}")
        body: dict[str, Any] = resp.json()
        if body.get("errors"):
            messages = "; ".join(e.get("message", "?") for e in body["errors"])
            raise GithubError(f"graphql errors: {messages}")
        data: dict[str, Any] = body["data"]
        return data

    def default_branch_sha(self, repo: str) -> str:
        owner, name = repo.split("/")
        data = self._graphql(
            "query($owner:String!,$name:String!){repository(owner:$owner,name:$name)"
            "{defaultBranchRef{target{oid}}}}",
            {"owner": owner, "name": name},
        )
        ref = (data.get("repository") or {}).get("defaultBranchRef")
        if not ref:
            raise GithubError(f"{repo}: no default branch")
        return str(ref["target"]["oid"])

    def iter_alerts(self, repo: str) -> Iterator[RawAlert]:
        owner, name = repo.split("/")
        cursor: str | None = None
        while True:
            data = self._graphql(_ALERTS_QUERY, {"owner": owner, "name": name, "cursor": cursor})
            repository = data.get("repository")
            if repository is None:
                raise GithubError(f"{repo}: not found or no access")
            page = repository["vulnerabilityAlerts"]
            for node in page["nodes"]:
                yield _parse_alert(repo, node)
            if not page["pageInfo"]["hasNextPage"]:
                return
            cursor = page["pageInfo"]["endCursor"]

    def tree(self, repo: str, sha: str) -> list[dict[str, Any]]:
        """Full recursive tree. Used for structure_hash and manifest discovery."""
        resp = self._request(
            "GET", f"{API}/repos/{repo}/git/trees/{sha}", params={"recursive": "1"}
        )
        if resp.status_code >= 400:
            raise GithubError(f"tree {repo}@{sha}: {resp.status_code}")
        body = resp.json()
        if body.get("truncated"):
            raise GithubError(
                f"{repo}@{sha}: git tree truncated — structure_hash would be unstable; "
                "fall back to a clone-based hash for this repo"
            )
        return list(body.get("tree") or [])

    def structure_hash(self, repo: str, sha: str, patterns: tuple[str, ...]) -> str:
        """Hash of every blob matching the invalidation globs, by path and content OID.

        Deterministic and clone-free. Changes exactly when a watched file's content or
        set membership changes — not on every commit (§8).
        """
        entries = sorted(
            (e["path"], e["sha"])
            for e in self.tree(repo, sha)
            if e.get("type") == "blob" and matches_any(e["path"], patterns)
        )
        return sha256_hex(*(f"{path}:{oid}" for path, oid in entries))

    def file_text(self, repo: str, path: str, ref: str) -> str | None:
        """Fetch one file's contents. Returns None for a missing path."""
        resp = self._request("GET", f"{API}/repos/{repo}/contents/{path}", params={"ref": ref})
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise GithubError(f"contents {repo}:{path}@{ref}: {resp.status_code}")
        body = resp.json()
        if body.get("encoding") != "base64":
            return None
        return base64.b64decode(body["content"]).decode("utf-8", errors="replace")

    def dismiss_alert(self, repo: str, number: int, *, reason: str, comment: str) -> None:
        """Gated by output.auto_dismiss_requires. Comment carries VEX code + evidence."""
        resp = self._request(
            "PATCH",
            f"{API}/repos/{repo}/dependabot/alerts/{number}",
            json={
                "state": "dismissed",
                "dismissed_reason": reason,
                "dismissed_comment": comment,
            },
        )
        if resp.status_code >= 400:
            raise GithubError(f"dismiss {repo}#{number}: {resp.status_code} {resp.text[:200]}")


def _parse_alert(repo: str, node: dict[str, Any]) -> RawAlert:
    vuln = node["securityVulnerability"]
    advisory = vuln["advisory"]
    cvss = advisory.get("cvss") or {}
    cve = next(
        (i["value"] for i in advisory.get("identifiers", []) if i.get("type") == "CVE"), None
    )
    patched = vuln.get("firstPatchedVersion") or {}
    return RawAlert(
        repo=repo,
        number=int(node["number"]),
        state=str(node["state"]).lower(),
        created_at=str(node["createdAt"]),
        manifest_path=str(node.get("vulnerableManifestPath") or ""),
        requirements=node.get("vulnerableRequirements"),
        scope_hint=(node.get("dependencyScope") or "").lower() or None,
        ghsa_id=str(advisory["ghsaId"]),
        cve_id=cve,
        package_name=str(vuln["package"]["name"]),
        ecosystem=str(vuln["package"]["ecosystem"]).lower(),
        patched_version=patched.get("identifier"),
        vulnerable_range=vuln.get("vulnerableVersionRange"),
        severity=(vuln.get("severity") or "").lower() or None,
        cvss_score=float(cvss["score"]) if cvss.get("score") is not None else None,
        cvss_vector=cvss.get("vectorString"),
        summary=str(advisory.get("summary") or ""),
    )
