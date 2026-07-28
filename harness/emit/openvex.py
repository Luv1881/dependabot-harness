"""OpenVEX v0.2.0 document generation.

Products are identified by PURL. A statement is emitted per (verdict, product) pair, and
`not_affected` always carries a justification because the spec requires one and a
consumer that cannot see why will not suppress the finding.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ..util import canonical_json, utcnow

CONTEXT = "https://openvex.dev/ns/v0.2.0"
AUTHOR = "triage-harness"

VEX_STATUSES = frozenset({"not_affected", "affected", "fixed", "under_investigation"})

_STATUS_FROM_VERDICT = {
    "not_affected": "not_affected",
    "affected": "affected",
    "fixed": "fixed",
    "could_not_determine": "under_investigation",
}


@dataclass(frozen=True)
class Statement:
    vulnerability: str
    products: tuple[str, ...]
    status: str
    justification: str | None = None
    impact_statement: str | None = None
    action_statement: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "vulnerability": {"name": self.vulnerability},
            "products": [{"@id": p} for p in self.products],
            "status": self.status,
        }
        if self.justification:
            payload["justification"] = self.justification
        if self.impact_statement:
            payload["impact_statement"] = self.impact_statement
        if self.action_statement:
            payload["action_statement"] = self.action_statement
        return payload


def statement_from_verdict(verdict: dict[str, Any], purl: str) -> Statement | None:
    """Translate one verdict. Returns None when the verdict has nothing assertable."""
    name = str(verdict.get("verdict", ""))
    status = _STATUS_FROM_VERDICT.get(name)
    if status is None:
        return None

    justification = verdict.get("vex_justification")
    if status == "not_affected" and not justification:
        return None

    vulnerability = str(verdict.get("ghsa_id") or verdict.get("cve_id") or "")
    if not vulnerability:
        return None

    return Statement(
        vulnerability=vulnerability,
        products=(purl,),
        status=status,
        justification=justification if status == "not_affected" else None,
        impact_statement=verdict.get("severity_rationale") if status == "not_affected" else None,
        action_statement=verdict.get("recommended_action") if status == "affected" else None,
    )


def build_document(
    repo: str, statements: list[Statement], *, timestamp: str | None = None
) -> dict[str, Any]:
    now = timestamp or utcnow()
    body = [s.to_dict() for s in statements]
    document = {
        "@context": CONTEXT,
        "@id": _document_id(repo, body),
        "author": AUTHOR,
        "timestamp": now,
        "version": 1,
        "statements": body,
    }
    return document


def _document_id(repo: str, statements: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256(canonical_json({"repo": repo, "s": statements}).encode()).hexdigest()
    return f"https://openvex.dev/docs/{repo.replace('/', '-')}-{digest[:16]}"
