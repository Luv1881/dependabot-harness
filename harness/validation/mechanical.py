"""Stage 7a — mechanical checks. Plain code, no model.

Every check answers a question that has an objectively verifiable answer. A verdict that
fails any of them is rejected and requeued rather than argued with.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..ecosystems import get_adapter
from ..schemas import SchemaViolation, validate

CISA_JUSTIFICATIONS = frozenset(
    {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }
)

CONTRADICTION_LEVEL = 4

DISMISSING_VERDICTS = frozenset({"not_affected", "fixed"})


@dataclass
class CheckResult:
    check: str
    passed: bool
    detail: str = ""


@dataclass
class MechanicalReport:
    results: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "failures": [{"check": f.check, "detail": f.detail} for f in self.failures],
            "checks_run": [r.check for r in self.results],
        }


def check_verdict(
    verdict: dict[str, Any],
    *,
    bundle: dict[str, Any] | None = None,
    repo_root: Path | None = None,
    ecosystem: str | None = None,
) -> MechanicalReport:
    """Run every check. All of them run, so the report lists every problem at once."""
    report = MechanicalReport()
    report.results.append(_schema(verdict))
    report.results.append(_justification(verdict))
    report.results.append(_confidence_ceiling(verdict, ecosystem))
    report.results.append(_contradiction(verdict, bundle))
    report.results.extend(_citations(verdict, repo_root))
    return report


def _schema(verdict: dict[str, Any]) -> CheckResult:
    try:
        validate("verdict", verdict)
    except SchemaViolation as exc:
        return CheckResult("schema", False, str(exc))
    return CheckResult("schema", True)


def _justification(verdict: dict[str, Any]) -> CheckResult:
    if verdict.get("vex_status") != "not_affected":
        return CheckResult("vex_justification", True)
    justification = verdict.get("vex_justification")
    if justification not in CISA_JUSTIFICATIONS:
        return CheckResult(
            "vex_justification",
            False,
            f"vex_status 'not_affected' requires a CISA justification code, got {justification!r}",
        )
    return CheckResult("vex_justification", True)


def _confidence_ceiling(verdict: dict[str, Any], ecosystem: str | None) -> CheckResult:
    if ecosystem is None:
        return CheckResult("confidence_ceiling", True, "no ecosystem supplied")
    adapter = get_adapter(ecosystem)
    if adapter is None:
        return CheckResult("confidence_ceiling", True, f"no adapter for {ecosystem!r}")
    ceiling = adapter.confidence_ceiling()
    confidence = float(verdict.get("confidence", 0.0))
    if confidence > ceiling:
        return CheckResult(
            "confidence_ceiling",
            False,
            f"confidence {confidence} exceeds the {ecosystem} ceiling of {ceiling}",
        )
    return CheckResult("confidence_ceiling", True)


def _contradiction(verdict: dict[str, Any], bundle: dict[str, Any] | None) -> CheckResult:
    """A dismissal while the tooling proved a call path is a contradiction.

    Covers `fixed` as well as `not_affected`: both close the alert, so both must be
    consistent with what the tooling actually measured.
    """
    if bundle is None or verdict.get("verdict") not in DISMISSING_VERDICTS:
        return CheckResult("reachability_contradiction", True)
    reachability = bundle.get("reachability") or {}
    if reachability.get("method") == "failed":
        return CheckResult("reachability_contradiction", True)
    level = int(reachability.get("level", 0))
    if level >= CONTRADICTION_LEVEL:
        return CheckResult(
            "reachability_contradiction",
            False,
            f"verdict {verdict.get('verdict')!r} contradicts reachability level {level}, "
            "which means a call path from an entry point was proven",
        )
    return CheckResult("reachability_contradiction", True)


def _citations(verdict: dict[str, Any], repo_root: Path | None) -> list[CheckResult]:
    """Every cited file must exist and every cited line must be within it."""
    citations = verdict.get("evidence_cited") or []
    if not citations:
        return [CheckResult("citations", True, "no citations to verify")]
    if repo_root is None:
        if verdict.get("verdict") in DISMISSING_VERDICTS:
            return [
                CheckResult(
                    "citations",
                    False,
                    "no checkout available to verify the citations behind a dismissal; "
                    "an unverifiable dismissal is not accepted",
                )
            ]
        return [CheckResult("citations", True, "no checkout available to verify against")]

    results: list[CheckResult] = []
    for citation in citations:
        path = str(citation.get("file", ""))
        line = int(citation.get("line", 0))
        target = _resolve(repo_root, path)
        if target is None or not target.is_file():
            results.append(
                CheckResult("citation_path", False, f"cited file does not exist: {path}")
            )
            continue
        try:
            total = len(target.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError as exc:
            results.append(CheckResult("citation_path", False, f"cannot read {path}: {exc}"))
            continue
        if line < 1 or line > total:
            results.append(
                CheckResult(
                    "citation_line",
                    False,
                    f"cited line {line} is outside {path}, which has {total} lines",
                )
            )
        else:
            results.append(CheckResult("citation_line", True, f"{path}:{line}"))
    return results


def _resolve(root: Path, relative: str) -> Path | None:
    try:
        resolved = (root / relative).resolve()
        base = root.resolve()
    except OSError:
        return None
    return resolved if resolved.is_relative_to(base) else None
