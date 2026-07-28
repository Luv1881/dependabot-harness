"""Entrypoint: run, resume, report.

`replay` lands with verdicts (M6). Listing it now would be a promise the pipeline
cannot yet keep.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from dataclasses import dataclass
from typing import Any

from .config import ConfigError, load_config, load_policy
from .db import Database
from .models import BudgetLedger
from .policy import PolicyEngine
from .scan import scan_public_repo
from .sources.github import GithubClient
from .stages.dedup import DedupReport, DedupStage, propagate_verdicts
from .stages.emit import EmitReport, EmitStage
from .stages.evidence import EvidenceReport, EvidenceStage
from .stages.ingest import IngestReport, IngestStage
from .stages.judgment import JudgmentReport, JudgmentStage
from .stages.policy import PolicyReport, PolicyStage
from .stages.recon import ReconReport, ReconStage
from .stages.validate import ValidationReport, ValidationStage

log = logging.getLogger("harness")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _new_run_id() -> str:
    return uuid.uuid4().hex[:16]


@dataclass
class RunOutcome:
    ingest: IngestReport
    policy: PolicyReport
    dedup: DedupReport
    recon: ReconReport
    evidence: EvidenceReport
    judgment: JudgmentReport
    validation: ValidationReport
    emit: EmitReport


def _execute(cfg_path: str, policy_path: str, run_id: str, *, resuming: bool) -> RunOutcome:
    cfg = load_config(cfg_path)
    engine = PolicyEngine(load_policy(policy_path))
    with Database(cfg.storage.db_path) as db:
        if resuming:
            run = db.get_run(run_id)
            if run is None:
                raise SystemExit(f"no such run: {run_id}")
            if run["config_hash"] != cfg.hash:
                raise SystemExit(
                    f"config changed since run {run_id} started "
                    f"({run['config_hash'][:12]} -> {cfg.hash[:12]}); start a new run"
                )
        db.start_run(run_id, cfg.hash)
        ingest_stage = IngestStage(cfg, db)
        try:
            ingest_report = ingest_stage.run(run_id)
            policy_report = PolicyStage(cfg, db, engine).run(run_id)
            ledger = BudgetLedger(cfg.budgets, db, run_id)
            dedup_report = DedupStage(cfg, db, ledger).run(run_id)
            recon_report = ReconStage(cfg, db, ledger).run(run_id)
            evidence_report = EvidenceStage(cfg, db).run(run_id)
            judgment_report = JudgmentStage(cfg, db, ledger).run(run_id)
            propagate_verdicts(db, run_id)
            validation_report = ValidationStage(cfg, db, ledger).run(run_id)
            emit_report = EmitStage(cfg, db, github=GithubClient(cfg.github)).run(run_id)
            db.finish_run(run_id, "complete")
        except BaseException:
            db.finish_run(run_id, "aborted")
            raise
        finally:
            ingest_stage.close()
        return RunOutcome(
            ingest=ingest_report,
            policy=policy_report,
            dedup=dedup_report,
            recon=recon_report,
            evidence=evidence_report,
            judgment=judgment_report,
            validation=validation_report,
            emit=emit_report,
        )


def cmd_run(args: argparse.Namespace) -> int:
    run_id = args.run_id or _new_run_id()
    _print_report(_execute(args.config, args.policy, run_id, resuming=False))
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    _print_report(_execute(args.config, args.policy, args.run_id, resuming=True))
    return 0


def cmd_scan_public(args: argparse.Namespace) -> int:
    """Triage a repository the harness does not administer, via OSV."""
    cfg = load_config(args.config)
    run_id = args.run_id or _new_run_id()
    result = scan_public_repo(
        cfg,
        args.repo,
        run_id,
        policy_path=args.policy,
        ref=args.ref,
        use_agents=None if args.agents == "auto" else args.agents == "on",
    )
    print(json.dumps(result.to_dict(), indent=2))

    discovery = result.discovery
    log.info(
        "discovery: %d manifests, %d dependencies (%d unpinned skipped), %d advisories",
        discovery.get("manifests", 0),
        discovery.get("dependencies", 0),
        discovery.get("unpinned_skipped", 0),
        discovery.get("advisories", 0),
    )
    if not result.agents_enabled:
        log.info("agent stages skipped: ANTHROPIC_API_KEY is not set")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with Database(cfg.storage.db_path) as db:
        run = db.get_run(args.run_id) if args.run_id else db.latest_run()
        if run is None:
            raise SystemExit("no runs recorded")
        run_id = str(run["run_id"])
        stages = {
            stage: db.stage_counts(run_id, stage)
            for stage in ("ingest", "policy", "dedup", "evidence", "judgment", "validate", "emit")
        }
        payload: dict[str, Any] = {
            "run_id": run_id,
            "status": run["status"],
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "config_hash": run["config_hash"],
            "stages": stages,
            "spend_usd": round(db.spend(run_id), 4),
            "open_wishlist_items": len(db.open_wishes()),
        }
        ingest = stages["ingest"]
        policy = stages["policy"]
        total = sum(ingest.values())
        policy_total = sum(policy.values())
        payload["metrics"] = {
            "total_alerts": total,
            "cache_replay_rate": round(ingest.get("skipped", 0) / total, 4) if total else 0.0,
            "cost_per_alert_usd": round(db.spend(run_id) / total, 6) if total else 0.0,
            "cleared_by_rules_pct": (
                round(policy.get("skipped", 0) / policy_total * 100, 2) if policy_total else 0.0
            ),
            "reaching_analysis": policy.get("done", 0),
        }
        print(json.dumps(payload, indent=2))
    return 0


def _print_report(outcome: RunOutcome) -> None:
    print(
        json.dumps(
            {
                "ingest": outcome.ingest.to_dict(),
                "policy": outcome.policy.to_dict(),
                "dedup": outcome.dedup.to_dict(),
                "recon": outcome.recon.to_dict(),
                "evidence": outcome.evidence.to_dict(),
                "judgment": outcome.judgment.to_dict(),
                "validation": outcome.validation.to_dict(),
                "emit": outcome.emit.to_dict(),
            },
            indent=2,
        )
    )
    ingest, stats = outcome.ingest, outcome.policy.stats
    log.info(
        "ingest: %d alerts, %d ingested, %d replayed (%.1f%%), %d failed",
        ingest.total,
        ingest.ingested,
        ingest.replayed,
        ingest.cache_replay_rate * 100,
        ingest.failed,
    )
    log.info(
        "policy: %d evaluated, %d cleared (%.1f%%), %d reaching analysis",
        stats.total,
        stats.cleared,
        stats.cleared / stats.total * 100 if stats.total else 0.0,
        stats.reaching_analysis,
    )
    dedup = outcome.dedup
    log.info(
        "dedup: %d clusters, %d judgment invocations saved (%d agent calls)",
        dedup.clusters,
        dedup.judgment_invocations_saved,
        dedup.agent_calls,
    )
    recon = outcome.recon
    log.info(
        "recon: %d generated, %d cached, $%.4f",
        recon.generated,
        recon.cached,
        recon.cost_usd,
    )
    evidence = outcome.evidence
    log.info(
        "evidence: %d analyzed, %d toolchain failures, shallow repos: %s",
        evidence.analyzed,
        evidence.failed_toolchain,
        evidence.shallow_repos or "none",
    )
    judgment = outcome.judgment
    log.info(
        "judgment: %d judged, %d undetermined (%d hit the tool cap), %d deferred on budget",
        judgment.judged,
        judgment.undetermined,
        judgment.cap_reached,
        judgment.deferred,
    )
    validation = outcome.validation
    log.info(
        "validation: %d checked, %d mechanically rejected, %d disputed (%.1f%%), "
        "%d queued for a human",
        validation.checked,
        validation.mechanically_rejected,
        validation.disputed,
        validation.disagreement_rate * 100,
        len(validation.human_queue),
    )
    log.info("emit: %d alerts auto-dismissed", outcome.emit.dismissed)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harness", description=__doc__)
    parser.add_argument("--config", default="config/harness.yaml")
    parser.add_argument("--policy", default="config/policy.yaml")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="ingest and process the configured repos")
    run.add_argument("--run-id", help="reuse an id instead of generating one")
    run.set_defaults(func=cmd_run)

    resume = sub.add_parser("resume", help="continue a run, redoing no completed stage")
    resume.add_argument("--run-id", required=True)
    resume.set_defaults(func=cmd_resume)

    scan = sub.add_parser(
        "scan-public",
        help="triage a public repository via OSV, without Dependabot admin scope",
    )
    scan.add_argument("--repo", required=True, help="owner/name")
    scan.add_argument("--ref", help="commit sha to analyse; defaults to the default branch")
    scan.add_argument("--run-id")
    scan.add_argument(
        "--agents",
        choices=("auto", "on", "off"),
        default="auto",
        help="auto enables agent stages only when ANTHROPIC_API_KEY is set",
    )
    scan.set_defaults(func=cmd_scan_public)

    report = sub.add_parser("report", help="metrics for a run (defaults to the latest)")
    report.add_argument("--run-id")
    report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        log.error("config: %s", exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
