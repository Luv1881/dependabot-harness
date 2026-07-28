"""Stage 4 — Recon. Agent, cached per repo per structure_hash.

Runs once per repo per structure hash rather than once per alert, so its cost amortizes
across every alert in that repo. This is the largest single cost lever in the system,
which is why cache correctness is treated as a first-class concern.

Context is assembled deterministically here. The agent receives an inventory; it never
reads the repository.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import HarnessConfig
from ..db import Database
from ..models import BudgetLedger, ModelClient, ModelError, ModelRequest
from ..models.client import ContextCeilingExceeded
from ..schemas import SchemaViolation, validate
from ..sources.checkout import CheckoutError, CheckoutManager
from ..util import RetryExhausted, age_days

log = logging.getLogger(__name__)

STAGE = "recon"
ROLE = "recon"

_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "recon.md"

MANIFEST_NAMES = frozenset(
    {
        "go.mod",
        "package.json",
        "pom.xml",
        "build.gradle",
        "Cargo.toml",
        "pyproject.toml",
        "requirements.txt",
        "Dockerfile",
        "docker-compose.yml",
        "Makefile",
        "Procfile",
    }
)
ENTRY_HINTS = ("routes", "handlers", "cmd", "main", "server", "api", "app", "controller")
DEPLOY_HINTS = (".tf", ".yaml", ".yml")
DEPLOY_DIR_HINTS = ("deploy", "k8s", "kubernetes", "helm", "charts", "infra", ".github")

_MAX_FILE_CHARS = 6_000
_MAX_TREE_ENTRIES = 400
_MAX_EXCERPTS = 25


@dataclass
class RepoReconResult:
    repo: str
    structure_hash: str
    cached: bool = False
    generated: bool = False
    cost_usd: float = 0.0
    error: str | None = None


@dataclass
class ReconReport:
    run_id: str
    repos: list[RepoReconResult] = field(default_factory=list)

    @property
    def generated(self) -> int:
        return sum(1 for r in self.repos if r.generated)

    @property
    def cached(self) -> int:
        return sum(1 for r in self.repos if r.cached)

    @property
    def cost_usd(self) -> float:
        return sum(r.cost_usd for r in self.repos)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generated": self.generated,
            "cached": self.cached,
            "cost_usd": round(self.cost_usd, 6),
            "repos": [r.__dict__ for r in self.repos],
        }


class ReconStage:
    def __init__(
        self,
        cfg: HarnessConfig,
        db: Database,
        ledger: BudgetLedger,
        *,
        client: ModelClient | None = None,
        checkouts: CheckoutManager | None = None,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.ledger = ledger
        self.client = client or ModelClient(cfg.model(ROLE), ledger)
        self.checkouts = checkouts or CheckoutManager(cfg.storage.checkout_dir, cfg.github)
        self.prompt = _PROMPT_PATH.read_text()

    def run(self, run_id: str) -> ReconReport:
        report = ReconReport(run_id=run_id)
        for repo in self.cfg.github.repos:
            report.repos.append(self.run_repo(run_id, repo))
        return report

    def run_repo(self, run_id: str, repo: str) -> RepoReconResult:
        snapshot = self.db.query(
            "SELECT commit_sha, structure_hash FROM repo_snapshots WHERE repo=? "
            "ORDER BY seen_at DESC, rowid DESC LIMIT 1",
            (repo,),
        )
        if not snapshot:
            return RepoReconResult(repo=repo, structure_hash="", error="no snapshot recorded")

        commit_sha = str(snapshot[0]["commit_sha"])
        structure_hash = str(snapshot[0]["structure_hash"])
        result = RepoReconResult(repo=repo, structure_hash=structure_hash)

        cached = self.db.get_architecture(repo, structure_hash)
        if cached and age_days(cached["generated_at"]) <= self.cfg.cache.architecture_ttl_days:
            result.cached = True
            return result

        decision = self.ledger.check(repo=repo)
        if not decision.allowed:
            result.error = f"budget {decision.scope} cap reached; deferred"
            log.warning("recon for %s deferred: %s", repo, result.error)
            return result

        try:
            checkout = self.checkouts.ensure(repo, commit_sha)
        except CheckoutError as exc:
            result.error = f"checkout unavailable: {exc}"
            self._wish(run_id, repo, f"could not clone {repo}@{commit_sha}: {exc}", "build_env")
            return result

        inventory = build_inventory(checkout.path, repo)
        request = ModelRequest(
            system=self.prompt,
            user=inventory,
            max_tokens=8_000,
            cacheable_prefix=self.prompt,
        )

        spend_before = self._recon_spend(repo)
        try:
            response = self.client.complete(request, repo=repo, stage=STAGE)
        except ContextCeilingExceeded as exc:
            result.error = str(exc)
            self._wish(
                run_id, repo, f"inventory exceeded the context ceiling: {exc}", "context_source"
            )
            return result
        except (ModelError, RetryExhausted) as exc:
            result.error = f"model call failed: {exc}"
            log.warning("recon for %s failed: %s", repo, exc)
            return result

        try:
            content = response.json()
            content.setdefault("repo", repo)
            content["commit_sha"] = commit_sha
            validate("architecture", content)
        except (ModelError, SchemaViolation) as exc:
            result.error = f"invalid architecture document: {exc}"
            return result

        cost = self._recon_spend(repo) - spend_before
        self.db.put_architecture(
            repo=repo,
            commit_sha=commit_sha,
            structure_hash=structure_hash,
            content=content,
            cost_usd=cost,
        )
        for gap in content.get("gaps") or []:
            self._wish(run_id, repo, str(gap), "context_source")

        result.generated = True
        result.cost_usd = cost
        return result

    def _recon_spend(self, repo: str) -> float:
        """Recon-stage spend only.

        Total repo spend would fold in other stages, inflating both the cached cost and
        the amortization metric the M5 gate reads.
        """
        rows = self.db.query(
            "SELECT COALESCE(SUM(cost_usd), 0) AS total FROM budget_ledger "
            "WHERE run_id=? AND repo=? AND stage=?",
            (self.ledger.run_id, repo, STAGE),
        )
        return float(rows[0]["total"])

    def _wish(self, run_id: str, repo: str, need: str, category: str) -> None:
        self.db.add_wish(run_id=run_id, repo=repo, need=need, category=category)

    def amortization(self, repo: str, alert_count: int) -> float:
        """Recon cost per alert for this repo. The M5 accept gate reads this."""
        if alert_count <= 0:
            return 0.0
        return self._recon_spend(repo) / alert_count


def build_inventory(repo_path: Path, repo: str) -> str:
    """Assemble the recon context deterministically.

    Bounded by construction: a capped directory listing, the manifests, and excerpts from
    files whose paths look like entry points or deployment descriptors. The agent is
    never invited to explore.
    """
    lines: list[str] = [f"# Repository: {repo}", ""]

    tree = _tree(repo_path)
    lines.append(f"## Directory tree ({len(tree)} entries shown)")
    lines.extend(f"- {p}" for p in tree)
    lines.append("")

    excerpts = _excerpts(repo_path, tree)
    lines.append(f"## File excerpts ({len(excerpts)} files)")
    for path, body in excerpts:
        lines.append(f"\n### {path}\n```\n{body}\n```")

    return "\n".join(lines)


def _tree(repo_path: Path) -> list[str]:
    skip = {".git", "node_modules", "vendor", "target", "dist", ".venv", "__pycache__"}
    entries: list[str] = []
    for path in sorted(repo_path.rglob("*")):
        if len(entries) >= _MAX_TREE_ENTRIES:
            break
        if not path.is_file() or any(part in skip for part in path.parts):
            continue
        entries.append(str(path.relative_to(repo_path)))
    return entries


def _excerpts(repo_path: Path, tree: list[str]) -> list[tuple[str, str]]:
    chosen: list[str] = []
    for relative in tree:
        name = Path(relative).name
        lowered = relative.lower()
        is_manifest = name in MANIFEST_NAMES
        is_entry = any(hint in lowered for hint in ENTRY_HINTS)
        is_deploy = lowered.endswith(DEPLOY_HINTS) and any(
            hint in lowered for hint in DEPLOY_DIR_HINTS
        )
        if is_manifest or is_entry or is_deploy:
            chosen.append(relative)
        if len(chosen) >= _MAX_EXCERPTS:
            break

    out: list[tuple[str, str]] = []
    for relative in chosen:
        try:
            body = (repo_path / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        out.append((relative, body[:_MAX_FILE_CHARS]))
    return out
