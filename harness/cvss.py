"""CVSS v3.x base score from a vector string.

OSV records a vector but often no numeric score, and the numeric score is what the
severity thresholds and the KEV rule actually compare against. Deriving it here keeps
those rules working on advisories that never passed through GitHub.

Implements the CVSS v3.1 base metric equation. A vector that cannot be parsed yields
None: an unscored advisory is unscored, not a zero.
"""

from __future__ import annotations

from dataclasses import dataclass

_ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
_PRIVILEGES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PRIVILEGES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_USER_INTERACTION = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


@dataclass(frozen=True)
class CvssScore:
    base: float
    severity: str
    vector: str


def parse_vector(vector: str | None) -> CvssScore | None:
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None

    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        if key and value:
            metrics[key.upper()] = value.upper()

    if any(key not in metrics for key in _REQUIRED):
        return None

    try:
        scope_changed = metrics["S"] == "C"
        privileges = _PRIVILEGES_CHANGED if scope_changed else _PRIVILEGES_UNCHANGED
        exploitability = (
            8.22
            * _ATTACK_VECTOR[metrics["AV"]]
            * _ATTACK_COMPLEXITY[metrics["AC"]]
            * privileges[metrics["PR"]]
            * _USER_INTERACTION[metrics["UI"]]
        )
        impact_base = 1 - (
            (1 - _IMPACT[metrics["C"]]) * (1 - _IMPACT[metrics["I"]]) * (1 - _IMPACT[metrics["A"]])
        )
    except KeyError:
        return None

    if scope_changed:
        impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
    else:
        impact = 6.42 * impact_base

    if impact <= 0:
        base = 0.0
    else:
        raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)
        base = _round_up(raw)

    return CvssScore(base=base, severity=severity_label(base), vector=vector)


def severity_label(score: float) -> str:
    """CVSS v3.1 qualitative rating. `none` is a real rating, not a missing value."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def _round_up(value: float) -> float:
    """CVSS rounds up to one decimal place, which ordinary rounding does not do."""
    scaled = int(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (scaled // 10000 + 1) / 10.0
