#!/usr/bin/env python
"""Generate the synthetic bootstrap golden set.

These cases are NOT hand-labeled real alerts. They exist so the eval harness has
something to score against on day one, and so the metric plumbing is itself tested.
Every record carries ``source: "synthetic"``.

The M4 accept gate requires real alerts labeled by a human. Replace or supplement these
with records carrying ``source: "hand_labeled"`` before trusting any number this
produces. `run_eval.py` reports the synthetic share of the set on every run so a
synthetic-only baseline can never be mistaken for a real one.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

ECOSYSTEMS = [
    ("go", "pkg:golang/github.com/{}/lib", "go.mod"),
    ("npm", "pkg:npm/{}", "package.json"),
    ("pip", "pkg:pypi/{}", "requirements.txt"),
    ("maven", "pkg:maven/com.{}.core/{}-databind", "pom.xml"),
    ("cargo", "pkg:cargo/{}", "Cargo.toml"),
]

WORDS = [
    "acme", "beacon", "cobalt", "delta", "ember", "fathom", "gravel", "harbor",
    "indigo", "juniper", "kelvin", "lumen", "mosaic", "nimbus", "onyx", "pivot",
    "quartz", "ripple", "summit", "tundra", "umber", "vertex", "willow", "xenon",
]


def build(count: int, seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    cases: list[dict[str, Any]] = []

    for index in range(count):
        ecosystem, purl_template, manifest = ECOSYSTEMS[index % len(ECOSYSTEMS)]
        word = WORDS[index % len(WORDS)]
        purl = purl_template.format(word, word) if "{}" in purl_template else purl_template
        shape = index % 10

        case: dict[str, Any] = {
            "case_id": f"synthetic-{index:04d}",
            "repo": f"my-org/service-{chr(ord('a') + index % 6)}",
            "ghsa_id": f"GHSA-{word[:4]}-{index:04d}-test",
            "ecosystem": ecosystem,
            "purl": purl,
            "manifest_path": manifest,
            "severity": rng.choice(["low", "moderate", "high", "critical"]),
            "cvss_score": round(rng.uniform(3.0, 9.9), 1),
            "epss_score": round(rng.uniform(0.0, 0.4), 4),
            "in_kev": False,
            "source": "synthetic",
        }

        if shape == 0:
            case.update(
                label="not_reachable",
                resolved_version="2.0.0",
                patched_version="1.9.0",
                dep_scope="runtime",
                is_direct=True,
                rationale="resolved version already above the patched version",
            )
        elif shape == 1:
            case.update(
                label="not_reachable",
                resolved_version="1.0.0",
                patched_version="1.5.0",
                dep_scope="runtime",
                is_direct=True,
                imports_scanned=["fmt", "os"],
                rationale="package never imported anywhere in the repository",
            )
        elif shape in (2, 3):
            case.update(
                label="reachable",
                resolved_version="1.0.0",
                patched_version="2.0.0",
                dep_scope="runtime",
                is_direct=True,
                symbols=["vulnlib.ParseHeader"],
                reachability_level=4,
                reachability_confidence=0.9,
                reachability_method="govulncheck",
                rationale="call path from an entry point reaches the vulnerable symbol",
            )
        elif shape == 4:
            case.update(
                label="reachable",
                resolved_version="1.0.0",
                patched_version="3.0.0",
                dep_scope="runtime",
                is_direct=True,
                in_kev=True,
                cvss_score=9.8,
                severity="critical",
                symbols=["vulnlib.Exec"],
                rationale="known exploited, direct dependency, critical severity",
            )
        elif shape == 5:
            case.update(
                label="not_reachable",
                resolved_version="1.0.0",
                patched_version="2.0.0",
                dep_scope="development",
                is_direct=True,
                production_build_targets=["cmd/api"],
                rationale="development-scope dependency, absent from production build targets",
            )
        elif shape == 6:
            case.update(
                label="unsure",
                resolved_version="1.0.0",
                patched_version="2.0.0",
                dep_scope="unknown",
                is_direct=None,
                reachability_method="failed",
                rationale="toolchain failed to resolve the project; genuinely undetermined",
            )
        elif shape == 7:
            case.update(
                label="reachable",
                resolved_version="1.0.0",
                patched_version="2.0.0",
                dep_scope="runtime",
                is_direct=False,
                symbols=[],
                reachability_level=2,
                reachability_confidence=0.5,
                reachability_method="govulncheck",
                rationale="imported, but the advisory carries no symbol data",
            )
        elif shape == 8:
            case.update(
                label="not_reachable",
                resolved_version="1.2.3",
                patched_version="1.2.4",
                dep_scope="runtime",
                is_direct=True,
                reachability_level=1,
                reachability_confidence=0.9,
                reachability_method="govulncheck",
                rationale="present in the tree but never imported",
            )
        else:
            case.update(
                label="reachable",
                resolved_version="0.9.0",
                patched_version="1.0.0",
                dep_scope="runtime",
                is_direct=True,
                symbols=["vulnlib.Handle"],
                reachability_level=5,
                reachability_confidence=0.95,
                reachability_method="govulncheck",
                rationale="call path carries attacker-controlled input",
            )

        cases.append(case)
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=120)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--out", default="eval/golden/synthetic.jsonl")
    args = parser.parse_args()

    cases = build(args.count, args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(c, sort_keys=True) + "\n" for c in cases))
    print(f"wrote {len(cases)} synthetic cases to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
