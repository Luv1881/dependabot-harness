"""SARIF 2.1.0 generation with a custom property bag.

`reachability_level`, `reachability_confidence`, `analysis_method` and
`validator_agreed` travel in `properties` so the GitHub Security tab surfaces the
reasoning rather than just the advisory text.
"""

from __future__ import annotations

from typing import Any

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"
TOOL_NAME = "triage-harness"

_LEVEL_FROM_VERDICT = {
    "affected": "error",
    "not_affected": "none",
    "fixed": "none",
    "could_not_determine": "warning",
}


def build_report(
    repo: str,
    findings: list[dict[str, Any]],
    *,
    tool_version: str = "0.1.0",
) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = str(finding.get("ghsa_id") or finding.get("alert_key", "unknown"))
        rules.setdefault(rule_id, _rule(rule_id, finding))
        results.append(_result(rule_id, finding))

    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": tool_version,
                        "informationUri": "https://github.com/triage-harness",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"repo": repo},
            }
        ],
    }


def _rule(rule_id: str, finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": rule_id.replace("-", ""),
        "shortDescription": {"text": str(finding.get("summary") or rule_id)},
        "fullDescription": {"text": str(finding.get("summary") or rule_id)},
        "helpUri": f"https://github.com/advisories/{rule_id}",
        "properties": {"security-severity": str(finding.get("cvss") or 0.0)},
    }


def _result(rule_id: str, finding: dict[str, Any]) -> dict[str, Any]:
    verdict = str(finding.get("verdict", "could_not_determine"))
    citation = (finding.get("evidence_cited") or [{}])[0]
    location_path = str(citation.get("file") or finding.get("manifest_path") or "unknown")
    line = int(citation.get("line") or 1)

    return {
        "ruleId": rule_id,
        "level": _LEVEL_FROM_VERDICT.get(verdict, "warning"),
        "message": {"text": _message(finding)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location_path},
                    "region": {"startLine": max(1, line)},
                }
            }
        ],
        "properties": {
            "reachability_level": finding.get("reachability_level"),
            "reachability_confidence": finding.get("reachability_confidence"),
            "analysis_method": finding.get("analysis_method"),
            "validator_agreed": finding.get("validator_agreed"),
            "verdict": verdict,
            "vex_justification": finding.get("vex_justification"),
            "purl": finding.get("purl"),
            "decided_by": finding.get("decided_by"),
            "needs_human": finding.get("needs_human"),
        },
    }


def _message(finding: dict[str, Any]) -> str:
    verdict = str(finding.get("verdict", "could_not_determine"))
    purl = finding.get("purl", "the dependency")
    if verdict == "affected":
        return (
            f"{purl}: reachable. {finding.get('severity_rationale') or ''} "
            f"{finding.get('recommended_action') or ''}"
        ).strip()
    if verdict == "not_affected":
        return f"{purl}: not affected ({finding.get('vex_justification')})."
    if verdict == "fixed":
        return f"{purl}: already at or above the patched version."
    return (
        f"{purl}: could not determine reachability. "
        f"{'; '.join(finding.get('unknowns') or []) or 'Human review required.'}"
    )
