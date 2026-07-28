"""Golden set loading and the held-out split.

Ground truth is ``reachable | not_reachable | unsure``. Predictions are the verdict enum.
The two vocabularies are deliberately different: a label describes the world, a verdict
describes what the harness concluded, and collapsing them hides exactly the errors this
set exists to measure.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

HOLDOUT_FRACTION = 0.2
HOLDOUT_SALT = "triage-harness-holdout-v1"


class Label(StrEnum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    UNSURE = "unsure"


class Split(StrEnum):
    TUNE = "tune"
    HOLDOUT = "holdout"


class DatasetError(ValueError):
    """A golden record is malformed or carries an unknown label."""


@dataclass(frozen=True)
class GoldenCase:
    case_id: str
    label: Label
    repo: str
    ghsa_id: str
    ecosystem: str
    purl: str
    resolved_version: str | None = None
    patched_version: str | None = None
    manifest_path: str = ""
    dep_scope: str | None = None
    is_direct: bool | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    in_kev: bool = False
    severity: str | None = None
    symbols: list[str] = field(default_factory=list)
    imports_scanned: list[str] | None = None
    production_build_targets: list[str] | None = None
    superseded_by: str | None = None
    reachability_level: int | None = None
    reachability_confidence: float | None = None
    reachability_method: str | None = None
    rationale: str = ""
    source: str = "synthetic"

    @property
    def split(self) -> Split:
        """Deterministic assignment: a case never moves between splits across runs."""
        digest = hashlib.sha256(f"{HOLDOUT_SALT}|{self.case_id}".encode()).hexdigest()
        bucket = int(digest[:8], 16) / 0xFFFFFFFF
        return Split.HOLDOUT if bucket < HOLDOUT_FRACTION else Split.TUNE

    @property
    def is_labeled(self) -> bool:
        return self.label is not Label.UNSURE

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> GoldenCase:
        try:
            label = Label(raw["label"])
        except (KeyError, ValueError) as exc:
            raise DatasetError(f"case {raw.get('case_id', '?')}: bad label: {exc}") from exc
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(raw) - known
        if unknown:
            raise DatasetError(f"case {raw.get('case_id', '?')}: unknown fields {sorted(unknown)}")
        payload = {k: v for k, v in raw.items() if k != "label"}
        return cls(label=label, **payload)


@dataclass
class GoldenSet:
    cases: list[GoldenCase]

    def __len__(self) -> int:
        return len(self.cases)

    def __iter__(self) -> Iterator[GoldenCase]:
        return iter(self.cases)

    def split(self, which: Split) -> GoldenSet:
        return GoldenSet([c for c in self.cases if c.split is which])

    @property
    def tune(self) -> GoldenSet:
        return self.split(Split.TUNE)

    @property
    def holdout(self) -> GoldenSet:
        return self.split(Split.HOLDOUT)

    def label_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for case in self.cases:
            counts[case.label.value] = counts.get(case.label.value, 0) + 1
        return counts

    def ecosystem_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for case in self.cases:
            counts[case.ecosystem] = counts.get(case.ecosystem, 0) + 1
        return counts


def load_golden(directory: str | Path) -> GoldenSet:
    path = Path(directory)
    if not path.is_dir():
        raise DatasetError(f"golden directory not found: {path}")
    cases: list[GoldenCase] = []
    seen: set[str] = set()
    for file in sorted(path.glob("*.jsonl")):
        for lineno, line in enumerate(file.read_text().splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise DatasetError(f"{file}:{lineno}: {exc}") from exc
            case = GoldenCase.from_dict(raw)
            if case.case_id in seen:
                raise DatasetError(f"{file}:{lineno}: duplicate case_id {case.case_id!r}")
            seen.add(case.case_id)
            cases.append(case)
    return GoldenSet(cases)
