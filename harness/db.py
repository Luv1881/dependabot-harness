"""SQLite schema, migrations, and DAO.

Every stage writes here before returning. ``resume --run-id X`` picks up exactly where a
killed process stopped by reading ``stage_results`` — no completed stage is redone.

Secrets are never stored. Nothing in this module accepts a token or key.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, cast

from .util import canonical_json, utcnow

SCHEMA_VERSION = 1

STAGES = ("ingest", "policy", "dedup", "evidence", "judgment", "validate", "emit")
TERMINAL_STATUSES = frozenset({"done", "skipped"})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
  run_id        TEXT PRIMARY KEY,
  started_at    TEXT NOT NULL,
  finished_at   TEXT,
  status        TEXT NOT NULL,      -- running|complete|aborted
  config_hash   TEXT NOT NULL
);

-- Stable across runs. This is the deduplication anchor.
CREATE TABLE IF NOT EXISTS alerts (
  alert_key     TEXT PRIMARY KEY,   -- sha256(ghsa_id|purl|resolved_version|manifest_path|repo)
  repo          TEXT NOT NULL,
  ghsa_id       TEXT NOT NULL,
  cve_id        TEXT,
  purl          TEXT NOT NULL,
  ecosystem     TEXT NOT NULL,
  resolved_ver  TEXT,
  patched_ver   TEXT,
  manifest_path TEXT NOT NULL,
  dep_scope     TEXT,               -- runtime|development|unknown
  is_direct     INTEGER,
  cvss_score    REAL,
  cvss_vector   TEXT,
  severity      TEXT,
  epss_score    REAL,
  in_kev        INTEGER,
  gh_alert_num  INTEGER NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  state         TEXT NOT NULL,      -- open|fixed|dismissed
  symbols_json  TEXT                -- OSV ecosystem_specific.imports, or NULL if absent
);
CREATE INDEX IF NOT EXISTS idx_alerts_repo ON alerts(repo);
CREATE INDEX IF NOT EXISTS idx_alerts_ghsa ON alerts(ghsa_id);
CREATE INDEX IF NOT EXISTS idx_alerts_purl ON alerts(purl);

CREATE TABLE IF NOT EXISTS stage_results (
  run_id        TEXT NOT NULL,
  alert_key     TEXT NOT NULL,
  stage         TEXT NOT NULL,      -- ingest|dedup|evidence|judgment|validate|emit
  status        TEXT NOT NULL,      -- pending|running|done|failed|skipped|budget_deferred
  payload_json  TEXT,
  error         TEXT,
  attempts      INTEGER DEFAULT 0,
  cost_usd      REAL DEFAULT 0,
  tokens_in     INTEGER DEFAULT 0,
  tokens_out    INTEGER DEFAULT 0,
  updated_at    TEXT NOT NULL,
  PRIMARY KEY (run_id, alert_key, stage)
);
CREATE INDEX IF NOT EXISTS idx_stage_status ON stage_results(run_id, stage, status);

-- Recon output, cached per repo, NOT per alert. The main cost lever.
CREATE TABLE IF NOT EXISTS architecture (
  repo           TEXT NOT NULL,
  commit_sha     TEXT NOT NULL,
  structure_hash TEXT NOT NULL,     -- hash of files matching invalidate_architecture_on_paths
  content_json   TEXT NOT NULL,
  generated_at   TEXT NOT NULL,
  cost_usd       REAL,
  PRIMARY KEY (repo, structure_hash)
);

-- ADDITIVE (see CLAUDE.md resolution 1): structure_hash is computed deterministically at
-- ingest so cache replay does not depend on an agent stage having already run.
CREATE TABLE IF NOT EXISTS repo_snapshots (
  repo           TEXT NOT NULL,
  commit_sha     TEXT NOT NULL,
  structure_hash TEXT NOT NULL,
  seen_at        TEXT NOT NULL,
  PRIMARY KEY (repo, commit_sha)
);
CREATE INDEX IF NOT EXISTS idx_snapshots_repo_seen ON repo_snapshots(repo, seen_at DESC);

CREATE TABLE IF NOT EXISTS dedup_clusters (
  cluster_id    TEXT NOT NULL,
  alert_key     TEXT NOT NULL,
  is_canonical  INTEGER NOT NULL,
  rationale     TEXT,
  PRIMARY KEY (cluster_id, alert_key)
);
CREATE INDEX IF NOT EXISTS idx_dedup_alert ON dedup_clusters(alert_key);

CREATE TABLE IF NOT EXISTS verdicts (
  alert_key       TEXT NOT NULL,
  run_id          TEXT NOT NULL,
  verdict_json    TEXT NOT NULL,    -- conforms to schemas/verdict.json
  validated       INTEGER,          -- 1 agreed, 0 disputed, NULL not run
  validator_notes TEXT,
  created_at      TEXT NOT NULL,
  -- ADDITIVE: the repo structure this verdict was produced against. Cache replay must
  -- compare against this exact value; correlating by timestamp is ambiguous whenever
  -- two snapshots land in the same second.
  structure_hash  TEXT,
  PRIMARY KEY (alert_key, run_id)
);
CREATE INDEX IF NOT EXISTS idx_verdicts_created ON verdicts(alert_key, created_at DESC);

CREATE TABLE IF NOT EXISTS budget_ledger (
  run_id TEXT, repo TEXT, alert_key TEXT, stage TEXT,
  cost_usd REAL, at TEXT
);
CREATE INDEX IF NOT EXISTS idx_ledger_run_repo ON budget_ledger(run_id, repo);
CREATE INDEX IF NOT EXISTS idx_ledger_alert ON budget_ledger(run_id, alert_key);

CREATE TABLE IF NOT EXISTS wishlist (
  id INTEGER PRIMARY KEY,
  run_id TEXT, alert_key TEXT, repo TEXT,
  need TEXT NOT NULL,               -- free text: what the agent could not get
  category TEXT,                    -- toolchain|credentials|context_source|build_env
  created_at TEXT, resolved_at TEXT
);
"""


@dataclass
class AlertRecord:
    """One Dependabot alert, enriched. Mirrors the ``alerts`` table exactly."""

    alert_key: str
    repo: str
    ghsa_id: str
    purl: str
    ecosystem: str
    manifest_path: str
    gh_alert_num: int
    first_seen_at: str
    last_seen_at: str
    state: str
    cve_id: str | None = None
    resolved_ver: str | None = None
    patched_ver: str | None = None
    dep_scope: str | None = None
    is_direct: bool | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    epss_score: float | None = None
    in_kev: bool | None = None
    symbols: list[str] | None = field(default=None)

    @property
    def symbols_known(self) -> bool:
        """§14.5 — advisories without symbol data cap reachability at level 2."""
        return bool(self.symbols)


class Database:
    """Thin DAO. Callers own transaction boundaries via :meth:`transaction`."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self.migrate()


    def migrate(self) -> None:
        self._conn.executescript(_SCHEMA)
        self._add_column_if_missing("verdicts", "structure_hash", "TEXT")
        self._conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )

    def _add_column_if_missing(self, table: str, column: str, decl: str) -> None:
        """Forward migration for DBs created before a column existed."""
        existing = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        else:
            self._conn.execute("COMMIT")


    def start_run(self, run_id: str, config_hash: str) -> None:
        self._conn.execute(
            "INSERT INTO runs(run_id, started_at, status, config_hash) VALUES(?,?,?,?) "
            "ON CONFLICT(run_id) DO UPDATE SET status='running'",
            (run_id, utcnow(), "running", config_hash),
        )

    def finish_run(self, run_id: str, status: str = "complete") -> None:
        self._conn.execute(
            "UPDATE runs SET status=?, finished_at=? WHERE run_id=?", (status, utcnow(), run_id)
        )

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        row = self._conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return cast("sqlite3.Row | None", row)

    def latest_run(self) -> sqlite3.Row | None:
        row = self._conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC, rowid DESC LIMIT 1"
        ).fetchone()
        return cast("sqlite3.Row | None", row)


    def upsert_alert(self, alert: AlertRecord) -> None:
        """Insert or refresh. ``first_seen_at`` is preserved across runs."""
        data = asdict(alert)
        symbols = data.pop("symbols")
        data["symbols_json"] = canonical_json(symbols) if symbols is not None else None
        data["is_direct"] = None if alert.is_direct is None else int(alert.is_direct)
        data["in_kev"] = None if alert.in_kev is None else int(alert.in_kev)
        columns = list(data)
        placeholders = ",".join("?" for _ in columns)
        updates = ",".join(
            f"{c}=excluded.{c}" for c in columns if c not in {"alert_key", "first_seen_at"}
        )
        self._conn.execute(
            f"INSERT INTO alerts({','.join(columns)}) VALUES({placeholders}) "
            f"ON CONFLICT(alert_key) DO UPDATE SET {updates}",
            [data[c] for c in columns],
        )

    def get_alert(self, alert_key: str) -> AlertRecord | None:
        row = self._conn.execute(
            "SELECT * FROM alerts WHERE alert_key=?", (alert_key,)
        ).fetchone()
        return _row_to_alert(row) if row else None

    def alerts_for_repo(self, repo: str) -> list[AlertRecord]:
        rows = self._conn.execute("SELECT * FROM alerts WHERE repo=?", (repo,)).fetchall()
        return [_row_to_alert(r) for r in rows]


    def record_stage(
        self,
        *,
        run_id: str,
        alert_key: str,
        stage: str,
        status: str,
        payload: Any = None,
        error: str | None = None,
        cost_usd: float = 0.0,
        tokens_in: int = 0,
        tokens_out: int = 0,
    ) -> None:
        """Write stage state. ``attempts`` increments on every call for this key.

        A ``payload`` of None leaves any existing payload in place. A later call that
        only changes status - requeueing, flagging - must not destroy the diagnostic the
        earlier call recorded.
        """
        if stage not in STAGES:
            raise ValueError(f"unknown stage {stage!r}")
        self._conn.execute(
            """
            INSERT INTO stage_results(
              run_id, alert_key, stage, status, payload_json, error,
              attempts, cost_usd, tokens_in, tokens_out, updated_at)
            VALUES(?,?,?,?,?,?,1,?,?,?,?)
            ON CONFLICT(run_id, alert_key, stage) DO UPDATE SET
              status=excluded.status,
              payload_json=COALESCE(excluded.payload_json, stage_results.payload_json),
              error=COALESCE(excluded.error, stage_results.error),
              attempts=stage_results.attempts + 1,
              cost_usd=stage_results.cost_usd + excluded.cost_usd,
              tokens_in=stage_results.tokens_in + excluded.tokens_in,
              tokens_out=stage_results.tokens_out + excluded.tokens_out,
              updated_at=excluded.updated_at
            """,
            (
                run_id,
                alert_key,
                stage,
                status,
                canonical_json(payload) if payload is not None else None,
                error,
                cost_usd,
                tokens_in,
                tokens_out,
                utcnow(),
            ),
        )

    def stage_status(self, run_id: str, alert_key: str, stage: str) -> str | None:
        row = self._conn.execute(
            "SELECT status FROM stage_results WHERE run_id=? AND alert_key=? AND stage=?",
            (run_id, alert_key, stage),
        ).fetchone()
        return str(row["status"]) if row else None

    def stage_payload(self, run_id: str, alert_key: str, stage: str) -> Any:
        row = self._conn.execute(
            "SELECT payload_json FROM stage_results WHERE run_id=? AND alert_key=? AND stage=?",
            (run_id, alert_key, stage),
        ).fetchone()
        if not row or row["payload_json"] is None:
            return None
        return json.loads(row["payload_json"])

    def is_stage_complete(self, run_id: str, alert_key: str, stage: str) -> bool:
        """Resume predicate: a completed stage is never redone."""
        return (self.stage_status(run_id, alert_key, stage) or "") in TERMINAL_STATUSES

    def stage_counts(self, run_id: str, stage: str) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM stage_results WHERE run_id=? AND stage=? "
            "GROUP BY status",
            (run_id, stage),
        ).fetchall()
        return {str(r["status"]): int(r["n"]) for r in rows}


    def record_snapshot(self, repo: str, commit_sha: str, structure_hash: str) -> None:
        self._conn.execute(
            "INSERT INTO repo_snapshots(repo, commit_sha, structure_hash, seen_at) "
            "VALUES(?,?,?,?) ON CONFLICT(repo, commit_sha) DO UPDATE SET "
            "structure_hash=excluded.structure_hash, seen_at=excluded.seen_at",
            (repo, commit_sha, structure_hash, utcnow()),
        )

    def last_structure_hash(self, repo: str, before_commit: str | None = None) -> str | None:
        """Most recently seen structure_hash for a repo, optionally excluding a commit.

        ``seen_at`` has second precision, so two snapshots recorded in the same second
        would tie. ``rowid`` breaks the tie by insertion order — without it, "did the
        structure change?" is nondeterministic on fast successive runs.
        """
        if before_commit:
            row = self._conn.execute(
                "SELECT structure_hash FROM repo_snapshots WHERE repo=? AND commit_sha!=? "
                "ORDER BY seen_at DESC, rowid DESC LIMIT 1",
                (repo, before_commit),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT structure_hash FROM repo_snapshots WHERE repo=? "
                "ORDER BY seen_at DESC, rowid DESC LIMIT 1",
                (repo,),
            ).fetchone()
        return str(row["structure_hash"]) if row else None

    def structure_hash_for_commit(self, repo: str, commit_sha: str) -> str | None:
        row = self._conn.execute(
            "SELECT structure_hash FROM repo_snapshots WHERE repo=? AND commit_sha=?",
            (repo, commit_sha),
        ).fetchone()
        return str(row["structure_hash"]) if row else None


    def get_architecture(self, repo: str, structure_hash: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM architecture WHERE repo=? AND structure_hash=?",
            (repo, structure_hash),
        ).fetchone()
        if not row:
            return None
        return {
            "content": json.loads(row["content_json"]),
            "commit_sha": row["commit_sha"],
            "generated_at": row["generated_at"],
            "cost_usd": row["cost_usd"],
        }

    def put_architecture(
        self,
        *,
        repo: str,
        commit_sha: str,
        structure_hash: str,
        content: dict[str, Any],
        cost_usd: float,
    ) -> None:
        self._conn.execute(
            "INSERT INTO architecture(repo, commit_sha, structure_hash, content_json, "
            "generated_at, cost_usd) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(repo, structure_hash) DO UPDATE SET "
            "commit_sha=excluded.commit_sha, content_json=excluded.content_json, "
            "generated_at=excluded.generated_at, cost_usd=excluded.cost_usd",
            (repo, commit_sha, structure_hash, canonical_json(content), utcnow(), cost_usd),
        )


    def put_verdict(
        self,
        *,
        alert_key: str,
        run_id: str,
        verdict: dict[str, Any],
        validated: bool | None = None,
        validator_notes: str | None = None,
        structure_hash: str | None = None,
    ) -> None:
        """``structure_hash`` is the repo state this verdict describes.

        Leaving it None makes the verdict ineligible for cache replay — a verdict whose
        subject state is unknown cannot be asserted about the current tree.
        """
        self._conn.execute(
            "INSERT INTO verdicts(alert_key, run_id, verdict_json, validated, "
            "validator_notes, created_at, structure_hash) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(alert_key, run_id) DO UPDATE SET "
            "verdict_json=excluded.verdict_json, validated=excluded.validated, "
            "validator_notes=excluded.validator_notes, created_at=excluded.created_at, "
            "structure_hash=excluded.structure_hash",
            (
                alert_key,
                run_id,
                canonical_json(verdict),
                None if validated is None else int(validated),
                validator_notes,
                utcnow(),
                structure_hash,
            ),
        )

    def latest_verdict(self, alert_key: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM verdicts WHERE alert_key=? ORDER BY created_at DESC LIMIT 1",
            (alert_key,),
        ).fetchone()
        if not row:
            return None
        return {
            "verdict": json.loads(row["verdict_json"]),
            "run_id": row["run_id"],
            "validated": row["validated"],
            "validator_notes": row["validator_notes"],
            "created_at": row["created_at"],
            "structure_hash": row["structure_hash"],
        }


    def record_cost(
        self,
        *,
        run_id: str,
        repo: str,
        stage: str,
        cost_usd: float,
        alert_key: str | None = None,
    ) -> None:
        """Every model call lands here. Recon uses ``alert_key=None`` (repo-level)."""
        self._conn.execute(
            "INSERT INTO budget_ledger(run_id, repo, alert_key, stage, cost_usd, at) "
            "VALUES(?,?,?,?,?,?)",
            (run_id, repo, alert_key, stage, cost_usd, utcnow()),
        )

    def spend(
        self, run_id: str, *, repo: str | None = None, alert_key: str | None = None
    ) -> float:
        clauses = ["run_id=?"]
        params: list[Any] = [run_id]
        if repo is not None:
            clauses.append("repo=?")
            params.append(repo)
        if alert_key is not None:
            clauses.append("alert_key=?")
            params.append(alert_key)
        row = self._conn.execute(
            f"SELECT COALESCE(SUM(cost_usd), 0) AS total FROM budget_ledger "
            f"WHERE {' AND '.join(clauses)}",
            params,
        ).fetchone()
        return float(row["total"])


    def add_wish(
        self,
        *,
        run_id: str,
        repo: str,
        need: str,
        category: str,
        alert_key: str | None = None,
    ) -> None:
        """What an agent needed but could not obtain. Never a guess (§8)."""
        self._conn.execute(
            "INSERT INTO wishlist(run_id, alert_key, repo, need, category, created_at) "
            "VALUES(?,?,?,?,?,?)",
            (run_id, alert_key, repo, need, category, utcnow()),
        )

    def open_wishes(self) -> Sequence[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM wishlist WHERE resolved_at IS NULL ORDER BY created_at DESC"
        ).fetchall()


    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return self._conn.execute(sql, params).fetchall()


def _row_to_alert(row: sqlite3.Row) -> AlertRecord:
    data = dict(row)
    symbols_json = data.pop("symbols_json", None)
    data["symbols"] = json.loads(symbols_json) if symbols_json else None
    data["is_direct"] = None if data["is_direct"] is None else bool(data["is_direct"])
    data["in_kev"] = None if data["in_kev"] is None else bool(data["in_kev"])
    return AlertRecord(**data)
