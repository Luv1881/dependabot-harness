#!/usr/bin/env python
"""Score a pipeline against the golden set.

Reports false-negative rate first because it is the metric that matters most: wrongly
dismissing a live vulnerability is worse than having no tool at all.

The holdout split is never scored unless ``--holdout`` is passed explicitly, and passing
it prints a warning. Tuning against the holdout destroys its only purpose.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.config import load_policy
from harness.evaluation.dataset import Split, load_golden
from harness.evaluation.runner import DeterministicPredictor, evaluate
from harness.policy import PolicyEngine


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--golden", default="eval/golden")
    parser.add_argument("--policy", default="config/policy.yaml")
    parser.add_argument("--baseline", help="path to a previous report to gate against")
    parser.add_argument("--out", help="write the report JSON here")
    parser.add_argument(
        "--holdout",
        action="store_true",
        help="score the held-out split; never use this while tuning",
    )
    parser.add_argument(
        "--allow-synthetic",
        action="store_true",
        help="report on a synthetic-only set; the accept gate still reports unsatisfied",
    )
    args = parser.parse_args()

    golden = load_golden(args.golden)
    if not golden:
        print(f"no golden cases found in {args.golden}", file=sys.stderr)
        return 1

    predictor = DeterministicPredictor(PolicyEngine(load_policy(args.policy)))
    split = Split.HOLDOUT if args.holdout else Split.TUNE
    subset = golden.split(split)

    if args.holdout:
        print(
            "WARNING: scoring the held-out split. Do not tune against these numbers.",
            file=sys.stderr,
        )

    report = evaluate(subset, predictor, split_name=split.value)
    payload = report.to_dict()
    payload["predictor"] = predictor.name
    payload["dataset"] = {
        "total": len(golden),
        "scored": len(subset),
        "labels": golden.label_counts(),
        "ecosystems": golden.ecosystem_counts(),
        "hand_labeled": sum(1 for c in golden if c.source == "hand_labeled"),
        "synthetic": sum(1 for c in golden if c.source == "synthetic"),
    }
    payload["accept_gate"] = _accept_gate(payload["dataset"])

    if args.baseline:
        baseline_payload = json.loads(Path(args.baseline).read_text())
        payload["vs_baseline"] = _compare_payloads(baseline_payload, payload)

    text = json.dumps(payload, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n")

    _print_headline(payload)
    gate: dict[str, object] = payload["accept_gate"]
    if not gate["satisfied"] and not args.allow_synthetic:
        print(
            "refusing to report a passing baseline from a set that is not hand-labeled; "
            "pass --allow-synthetic to acknowledge this is a bootstrap number",
            file=sys.stderr,
        )
        return 2
    return 0


MIN_MEANINGFUL_HOLDOUT = 30


def _accept_gate(dataset: dict[str, int]) -> dict[str, object]:
    hand = dataset["hand_labeled"]
    return {
        "requires_hand_labeled_cases": 100,
        "hand_labeled_present": hand,
        "satisfied": hand >= 100,
        "note": (
            "baseline is synthetic-only and cannot satisfy the M4 gate"
            if hand < 100
            else "hand-labeled set meets the required size"
        ),
    }


def _compare_payloads(
    baseline: dict[str, object], candidate: dict[str, object]
) -> dict[str, object]:
    fn_delta = float(candidate["false_negative_rate"]) - float(baseline["false_negative_rate"])
    cost_delta = float(candidate["mean_cost_per_alert_usd"]) - float(
        baseline["mean_cost_per_alert_usd"]
    )
    return {
        "false_negative_rate_delta": round(fn_delta, 4),
        "cost_delta_usd": round(cost_delta, 6),
        "accepted": fn_delta <= 0,
        "reason": (
            "false-negative rate rose; rejected regardless of cost improvement"
            if fn_delta > 0
            else "false-negative rate held or improved"
        ),
    }


def _print_headline(payload: dict[str, object]) -> None:
    dataset = payload["dataset"]
    gate = payload["accept_gate"]
    confusion = payload["confusion"]
    reachable = confusion["true_positive"] + confusion["false_negative"]
    print(
        f"\nFN rate {payload['false_negative_rate']:.2%} "
        f"({payload['false_negatives']} of {reachable} reachable) | "
        f"FP rate {payload['false_positive_rate']:.2%} | "
        f"could-not-determine {payload['could_not_determine_rate']:.2%}",
        file=sys.stderr,
    )
    scored = int(dataset["scored"])
    if payload["split"] == "holdout" and scored < MIN_MEANINGFUL_HOLDOUT:
        print(
            f"holdout has {scored} cases; below {MIN_MEANINGFUL_HOLDOUT} the confidence "
            "interval on the false-negative rate is too wide to detect a regression",
            file=sys.stderr,
        )
    if not gate["satisfied"]:
        print(
            f"accept gate NOT satisfied: {dataset['hand_labeled']} hand-labeled cases, "
            f"{dataset['synthetic']} synthetic. {gate['note']}.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    raise SystemExit(main())
