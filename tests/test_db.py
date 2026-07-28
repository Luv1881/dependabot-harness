from __future__ import annotations

from harness.db import AlertRecord, Database
from harness.util import utcnow


def make_alert(key: str = "k1", repo: str = "org/repo", **kw: object) -> AlertRecord:
    defaults: dict[str, object] = dict(
        alert_key=key,
        repo=repo,
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        purl="pkg:golang/example.com/x",
        ecosystem="go",
        manifest_path="go.mod",
        gh_alert_num=1,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        state="open",
    )
    defaults.update(kw)
    return AlertRecord(**defaults)  # type: ignore[arg-type]


class TestAlertRoundTrip:
    def test_upsert_and_read_back(self, db: Database) -> None:
        db.upsert_alert(make_alert(symbols=["pkg.Func"], is_direct=True, in_kev=False))
        got = db.get_alert("k1")
        assert got is not None
        assert got.symbols == ["pkg.Func"]
        assert got.is_direct is True
        assert got.in_kev is False

    def test_null_booleans_survive_as_none(self, db: Database) -> None:
        """`is_direct=None` means undecidable — it must never round-trip as False."""
        db.upsert_alert(make_alert(is_direct=None, in_kev=None))
        got = db.get_alert("k1")
        assert got is not None
        assert got.is_direct is None
        assert got.in_kev is None

    def test_first_seen_at_preserved_on_update(self, db: Database) -> None:
        original = make_alert(first_seen_at="2020-01-01T00:00:00+00:00")
        db.upsert_alert(original)
        db.upsert_alert(make_alert(first_seen_at="2030-01-01T00:00:00+00:00", state="fixed"))
        got = db.get_alert("k1")
        assert got is not None
        assert got.first_seen_at == "2020-01-01T00:00:00+00:00"
        assert got.state == "fixed"

    def test_symbols_absent_is_distinct_from_empty(self, db: Database) -> None:
        db.upsert_alert(make_alert(key="none", symbols=None))
        db.upsert_alert(make_alert(key="empty", symbols=[]))
        assert db.get_alert("none").symbols is None  # type: ignore[union-attr]
        assert db.get_alert("empty").symbols == []  # type: ignore[union-attr]


class TestStageResults:
    def test_resume_predicate(self, db: Database) -> None:
        db.record_stage(run_id="r1", alert_key="k1", stage="ingest", status="pending")
        assert not db.is_stage_complete("r1", "k1", "ingest")
        db.record_stage(run_id="r1", alert_key="k1", stage="ingest", status="done")
        assert db.is_stage_complete("r1", "k1", "ingest")

    def test_skipped_counts_as_complete(self, db: Database) -> None:
        """A cache-replayed alert must not be reprocessed on resume."""
        db.record_stage(run_id="r1", alert_key="k1", stage="ingest", status="skipped")
        assert db.is_stage_complete("r1", "k1", "ingest")

    def test_failed_is_not_complete(self, db: Database) -> None:
        db.record_stage(run_id="r1", alert_key="k1", stage="ingest", status="failed")
        assert not db.is_stage_complete("r1", "k1", "ingest")

    def test_attempts_and_cost_accumulate(self, db: Database) -> None:
        for _ in range(3):
            db.record_stage(
                run_id="r1",
                alert_key="k1",
                stage="judgment",
                status="failed",
                cost_usd=0.01,
                tokens_in=100,
            )
        row = db.query(
            "SELECT attempts, cost_usd, tokens_in FROM stage_results WHERE alert_key='k1'"
        )[0]
        assert row["attempts"] == 3
        assert abs(row["cost_usd"] - 0.03) < 1e-9
        assert row["tokens_in"] == 300

    def test_payload_round_trip(self, db: Database) -> None:
        db.record_stage(
            run_id="r1",
            alert_key="k1",
            stage="ingest",
            status="skipped",
            payload={"reason": "cache_replay", "n": 2},
        )
        assert db.stage_payload("r1", "k1", "ingest") == {"reason": "cache_replay", "n": 2}

    def test_runs_are_isolated(self, db: Database) -> None:
        db.record_stage(run_id="r1", alert_key="k1", stage="ingest", status="done")
        assert not db.is_stage_complete("r2", "k1", "ingest")


class TestSnapshots:
    def test_last_hash_excludes_named_commit(self, db: Database) -> None:
        db.record_snapshot("org/repo", "sha_old", "hash_a")
        db.record_snapshot("org/repo", "sha_new", "hash_b")
        assert db.last_structure_hash("org/repo", before_commit="sha_new") == "hash_a"
        assert db.last_structure_hash("org/repo") == "hash_b"

    def test_unknown_repo_returns_none(self, db: Database) -> None:
        assert db.last_structure_hash("org/nope") is None


class TestBudget:
    def test_repo_scoped_spend_includes_repo_level_recon(self, db: Database) -> None:
        """Recon is charged to the repo with alert_key NULL (CLAUDE.md resolution 6)."""
        db.record_cost(run_id="r1", repo="org/a", stage="recon", cost_usd=0.50)
        db.record_cost(run_id="r1", repo="org/a", stage="judgment", cost_usd=0.10, alert_key="k1")
        db.record_cost(run_id="r1", repo="org/b", stage="judgment", cost_usd=0.20, alert_key="k2")

        assert abs(db.spend("r1") - 0.80) < 1e-9
        assert abs(db.spend("r1", repo="org/a") - 0.60) < 1e-9
        assert abs(db.spend("r1", alert_key="k1") - 0.10) < 1e-9


class TestVerdicts:
    def test_latest_verdict_by_created_at(self, db: Database) -> None:
        db.put_verdict(alert_key="k1", run_id="r1", verdict={"verdict": "affected"})
        latest = db.latest_verdict("k1")
        assert latest is not None
        assert latest["verdict"]["verdict"] == "affected"
        assert latest["validated"] is None

    def test_validated_tristate(self, db: Database) -> None:
        db.put_verdict(alert_key="k1", run_id="r1", verdict={}, validated=False)
        assert db.latest_verdict("k1")["validated"] == 0  # type: ignore[index]


class TestPayloadPreservation:
    """A status-only update must not discard the diagnostic an earlier call wrote."""

    def test_none_payload_keeps_the_existing_one(self, db: Database) -> None:
        db.record_stage(
            run_id="r1",
            alert_key="k1",
            stage="evidence",
            status="done",
            payload={"reachability": {"method": "failed", "error": "not installed on PATH"}},
        )
        db.record_stage(
            run_id="r1", alert_key="k1", stage="evidence", status="failed", error="shallow"
        )

        payload = db.stage_payload("r1", "k1", "evidence")
        assert payload["reachability"]["error"] == "not installed on PATH"
        assert db.stage_status("r1", "k1", "evidence") == "failed"

    def test_an_explicit_payload_still_replaces(self, db: Database) -> None:
        db.record_stage(
            run_id="r1", alert_key="k1", stage="evidence", status="done", payload={"a": 1}
        )
        db.record_stage(
            run_id="r1", alert_key="k1", stage="evidence", status="done", payload={"b": 2}
        )
        assert db.stage_payload("r1", "k1", "evidence") == {"b": 2}

    def test_an_earlier_error_survives_a_status_only_update(self, db: Database) -> None:
        db.record_stage(
            run_id="r1",
            alert_key="k1",
            stage="evidence",
            status="failed",
            error="govulncheck: not installed on PATH",
        )
        db.record_stage(run_id="r1", alert_key="k1", stage="evidence", status="failed")
        row = db.query("SELECT error FROM stage_results WHERE alert_key='k1'")[0]
        assert "not installed" in row["error"]
