"""Triage a public repository the harness does not administer.

Same pipeline, different alert source. Everything downstream of ingest is unchanged,
which is the point: if the OSV path produces the same `RawAlert` shape, the deterministic
stages either work against a real project or they do not.

Agent stages are skipped unless a key is configured, so the deterministic half can be
exercised against real data for free.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field, replace
from typing import Any

from .config import HarnessConfig, load_policy
from .db import Database
from .models import BudgetLedger
from .policy import PolicyEngine
from .sources.checkout import CheckoutManager
from .sources.github import GithubClient
from .sources.osv_scan import OsvAlertSource
from .stages.dedup import DedupStage, propagate_verdicts
from .stages.emit import EmitStage
from .stages.evidence import EvidenceStage
from .stages.ingest import IngestStage
from .stages.judgment import JudgmentStage
from .stages.policy import PolicyStage
from .stages.recon import ReconStage
from .stages.validate import ValidationStage

log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    repo: str
    run_id: str
    commit_sha: str = ""
    agents_enabled: bool = False
    discovery: dict[str, Any] = field(default_factory=dict)
    stages: dict[str, Any] = field(default_factory=dict)
    spend_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "run_id": self.run_id,
            "commit_sha": self.commit_sha,
            "agents_enabled": self.agents_enabled,
            "discovery": self.discovery,
            "stages": self.stages,
            "spend_usd": round(self.spend_usd, 6),
        }


def agents_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def scoped_config(cfg: HarnessConfig, repo: str) -> HarnessConfig:
    """A config whose repo allowlist is exactly this one repository.

    Stages iterate the allowlist, so scoping it here keeps a public scan from touching
    whatever the operator happens to have configured for their own fleet.
    """
    return replace(cfg, github=replace(cfg.github, repos=(repo,)))


def scan_public_repo(
    cfg: HarnessConfig,
    repo: str,
    run_id: str,
    *,
    policy_path: str = "config/policy.yaml",
    ref: str | None = None,
    use_agents: bool | None = None,
) -> ScanResult:
    enabled = agents_available() if use_agents is None else use_agents
    scoped = scoped_config(cfg, repo)
    result = ScanResult(repo=repo, run_id=run_id, agents_enabled=enabled)

    github = GithubClient(scoped.github)
    checkouts = CheckoutManager(scoped.storage.checkout_dir, scoped.github)
    commit_sha = ref or github.default_branch_sha(repo)
    result.commit_sha = commit_sha

    checkout = checkouts.ensure(repo, commit_sha)
    source = OsvAlertSource(github, checkout.path)

    with Database(scoped.storage.db_path) as db:
        db.start_run(run_id, scoped.hash)
        ledger = BudgetLedger(scoped.budgets, db, run_id)

        try:
            ingest = IngestStage(scoped, db, github=source)
            result.stages["ingest"] = ingest.run(run_id).to_dict()
            result.discovery = source.stats.to_dict()

            engine = PolicyEngine(load_policy(policy_path))
            result.stages["policy"] = (
                PolicyStage(scoped, db, engine, checkouts=checkouts).run(run_id).to_dict()
            )

            result.stages["dedup"] = (
                DedupStage(scoped, db, ledger, use_agent=enabled).run(run_id).to_dict()
            )

            if enabled:
                result.stages["recon"] = (
                    ReconStage(scoped, db, ledger, checkouts=checkouts).run(run_id).to_dict()
                )

            result.stages["evidence"] = (
                EvidenceStage(scoped, db, checkouts=checkouts).run(run_id).to_dict()
            )

            if enabled:
                result.stages["judgment"] = (
                    JudgmentStage(scoped, db, ledger, checkouts=checkouts).run(run_id).to_dict()
                )
                propagate_verdicts(db, run_id)
                result.stages["validation"] = (
                    ValidationStage(scoped, db, ledger, checkouts=checkouts).run(run_id).to_dict()
                )

            result.stages["emit"] = EmitStage(scoped, db, github=None).run(run_id).to_dict()
            db.finish_run(run_id, "complete")
        except BaseException:
            db.finish_run(run_id, "aborted")
            raise
        finally:
            source.close()

        result.spend_usd = db.spend(run_id)

    return result
