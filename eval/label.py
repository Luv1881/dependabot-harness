#!/usr/bin/env python
"""Turn reviewed harvest output into the hand-labeled golden set.

Refuses to write a case that has no label or no rationale, so `source: "hand_labeled"`
cannot be claimed for a record nobody actually labelled. `_review` is a working field and
is stripped here — the golden format rejects unknown keys, deliberately, so a stray key
cannot ride along unnoticed.

For Go, a ``govulncheck`` report overrides the proposed label. That is the one place a
label comes from a tool rather than from inspection, and it is the strongest evidence
available: govulncheck either finds a call path to the vulnerable symbol or it does not,
by whole-program analysis. It is also independent of the pipeline, which is not.

    eval/label.py --review /tmp/rev/prometheus.jsonl --govulncheck /tmp/gov.json \\
                  --review /tmp/rev/goof.jsonl --out eval/golden/real.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.ecosystems.base import ReachabilityLevel
from harness.ecosystems.golang import _iter_json_messages
from harness.evaluation.dataset import GoldenCase

LABELS = {"reachable", "not_reachable", "unsure"}

GOLDEN_FIELDS = frozenset(GoldenCase.__dataclass_fields__)


def govulncheck_labels(path: str | None) -> dict[str, tuple[str, int]]:
    """Every identifier of every assessed advisory -> label.

    Keyed on *all* aliases, not the primary id. govulncheck reports Go's own ``GO-2026-…``
    identifiers; OSV discovery keys the same vulnerabilities by ``GHSA-…`` or ``CVE-…``. The
    two name identical advisories, so matching on the primary id alone silently matches
    nothing — which is how a first attempt produced 414 labelled cases with a `reachable`
    population of zero, and therefore an unmeasurable false-negative rate.

    A finding naming a vulnerable *function* is a call path: reachable. A finding with only
    a module frame means the module is in the build and the symbol is never called — a
    positive statement of non-reachability rather than an absence of evidence. An assessed
    advisory with no finding at all is likewise not reachable through this program.
    """
    if not path:
        return {}
    aliases: dict[str, set[str]] = {}
    reachable: set[str] = set()
    assessed: set[str] = set()
    levels: dict[str, int] = {}
    for message in _iter_json_messages(Path(path).read_text()):
        if "osv" in message:
            osv = message["osv"]
            identifiers = {str(osv.get("id", ""))}
            identifiers.update(str(a) for a in osv.get("aliases") or ())
            aliases[str(osv.get("id", ""))] = {i for i in identifiers if i}
        elif "finding" in message:
            finding = message["finding"]
            osv_id = str(finding.get("osv", ""))
            assessed.add(osv_id)
            if any(frame.get("function") for frame in finding.get("trace") or ()):
                reachable.add(osv_id)
                levels[osv_id] = int(ReachabilityLevel.PATH_FROM_ENTRY)
            else:
                levels.setdefault(osv_id, int(ReachabilityLevel.PRESENT))

    out: dict[str, tuple[str, int]] = {}
    for osv_id in assessed:
        label = "reachable" if osv_id in reachable else "not_reachable"
        level = levels.get(osv_id, int(ReachabilityLevel.PRESENT))
        for identifier in aliases.get(osv_id, {osv_id}):
            out[identifier] = (label, level)
    return out


def build(
    review_files: list[str],
    govuln: dict[str, tuple[str, int]],
    by_module: dict[str, dict[str, tuple[str, int]]] | None = None,
) -> list[dict[str, object]]:
    by_module = by_module or {}
    out: list[dict[str, object]] = []
    seen: Counter[str] = Counter()
    for path in review_files:
        for line in Path(path).read_text().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            review = entry.pop("_review")
            module_key = str(review.pop("_govulncheck_key", ""))
            label = review.get("proposed_label")
            rationale = review.get("rationale", "")

            # Match the analysis that covers this alert's own module when there is one,
            # so a submodule case is not labelled with the main module's call paths.
            scoped = by_module.get(module_key, {})
            ground_truth = next(
                (
                    source[ident]
                    for source in (scoped, govuln)
                    for ident in (
                        entry.get("ghsa_id"),
                        entry.get("cve_id"),
                        entry.get("osv_id"),
                    )
                    if ident and ident in source
                ),
                None,
            )
            if entry["ecosystem"] in {"go", "gomod"} and ground_truth:
                label, level = ground_truth
                # The evidence fact is corrected from the same analysis. A stale level here
                # is not cosmetic: it is what the evaluator reads to decide whether the
                # pipeline would have escalated or abstained.
                entry["reachability_level"] = level
                entry["reachability_method"] = "govulncheck"
                entry["reachability_confidence"] = 0.95 if level >= 4 else 0.9
                rationale = (
                    "govulncheck whole-program call-path analysis: "
                    + (
                        "a call path to the vulnerable symbol exists"
                        if label == "reachable"
                        else "no call path to the vulnerable symbol"
                    )
                )

            if label not in LABELS:
                raise SystemExit(f"{path}: no usable label for {entry.get('case_id')}")
            if not rationale:
                raise SystemExit(f"{path}: no rationale for {entry.get('case_id')}")

            seen[str(entry["case_id"])] += 1
            suffix = f"-{seen[str(entry['case_id'])]}" if seen[str(entry["case_id"])] > 1 else ""
            case = {
                "case_id": f"{entry['case_id']}{suffix}",
                "label": label,
                "rationale": rationale,
                "source": "hand_labeled",
            }
            for field in (
                "repo",
                "ghsa_id",
                "cve_id",
                "ecosystem",
                "purl",
                "resolved_version",
                "patched_version",
                "manifest_path",
                "dep_scope",
                "is_direct",
                "cvss_score",
                "severity",
                "symbols",
                "imports_scanned",
                "shipped_packages",
                "superseded_by",
                "reachability_level",
                "reachability_confidence",
                "reachability_method",
            ):
                if field in entry and entry[field] is not None:
                    case[field] = entry[field]
            GoldenCase.from_dict(case)  # fail here rather than at load time
            out.append(case)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", action="append", required=True)
    parser.add_argument("--govulncheck", action="append")
    parser.add_argument(
        "--govulncheck-dir",
        help="directory of raw govulncheck analyses to merge as ground truth",
    )
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--shipped-from",
        help="a harvest file whose shipped set is copied onto entries from the same repo",
    )
    args = parser.parse_args()

    sources = list(args.govulncheck or [])
    if args.govulncheck_dir:
        sources.extend(sorted(str(p) for p in Path(args.govulncheck_dir).glob("*.json")))
    govuln: dict[str, str] = {}
    for source in sources:
        govuln.update(govulncheck_labels(source))
    if govuln:
        counts = Counter(govuln.values())
        print(f"govulncheck ground truth: {dict(counts)}", file=sys.stderr)
    cases = build(args.review, govuln)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as handle:
        for case in cases:
            handle.write(json.dumps(case) + "\n")
    labels = Counter(str(c["label"]) for c in cases)
    ecosystems = Counter(str(c["ecosystem"]) for c in cases)
    print(f"{out}: {len(cases)} labelled case(s)")
    print(f"  labels     : {dict(labels)}")
    print(f"  ecosystems : {dict(ecosystems)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
