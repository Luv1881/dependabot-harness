"""Advisory cache robustness.

The cache holds third-party feed data keyed by advisory id, and those ids can come from
model-supplied tool arguments. Two properties matter: a key can never choose where a
write lands, and a damaged entry is a miss rather than an exception — a truncated file on
one operator's disk is not a reason to abort a fleet-wide triage run.
"""

from __future__ import annotations

import json
from pathlib import Path

from harness.sources._cache import JsonCache


class TestKeysAreNotFilenames:
    def test_a_traversal_key_cannot_escape_the_cache_directory(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv")
        cache.put("../../../../tmp/PWNED", {"x": 1})
        written = [p for p in tmp_path.rglob("*.json")]
        assert len(written) == 1
        assert written[0].parent == tmp_path / "osv"
        assert not Path("/tmp/PWNED.json").exists()

    def test_a_key_with_a_separator_is_hashed_not_nested(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv")
        cache.put("a/b", {"x": 1})
        assert cache.get("a/b") == {"x": 1}
        assert next(iter((tmp_path / "osv").iterdir())).name.count(".json") == 1

    def test_distinct_keys_get_distinct_files(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv")
        cache.put("GHSA-aaaa-bbbb-cccc", {"x": 1})
        cache.put("GHSA-dddd-eeee-ffff", {"x": 2})
        assert cache.get("GHSA-aaaa-bbbb-cccc") == {"x": 1}
        assert cache.get("GHSA-dddd-eeee-ffff") == {"x": 2}


class TestMalformedEntriesAreMisses:
    def _store(self, cache: JsonCache, key: str, raw: str) -> None:
        cache._path(key).write_text(raw)

    def test_a_missing_key_is_a_miss(self, tmp_path: Path) -> None:
        assert JsonCache(tmp_path, "osv").get("absent") is None

    def test_an_empty_object_is_a_miss(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv")
        self._store(cache, "k", "{}")
        assert cache.get("k") is None

    def test_a_missing_timestamp_is_a_miss(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv")
        self._store(cache, "k", json.dumps({"value": {"x": 1}}))
        assert cache.get("k") is None

    def test_a_non_string_timestamp_is_a_miss(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv")
        self._store(cache, "k", json.dumps({"fetched_at": 12345, "value": {"x": 1}}))
        assert cache.get("k") is None

    def test_an_unparsable_timestamp_is_a_miss(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv")
        self._store(cache, "k", json.dumps({"fetched_at": "not-a-date", "value": {"x": 1}}))
        assert cache.get("k") is None

    def test_truncated_json_is_a_miss(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv")
        self._store(cache, "k", '{"fetched_at": "2026-01-01T00:00:00+00:00", "value":')
        assert cache.get("k") is None

    def test_a_json_scalar_is_a_miss(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv")
        self._store(cache, "k", "42")
        assert cache.get("k") is None


class TestRoundTrip:
    def test_a_value_survives_a_put_get(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv")
        cache.put("GHSA-aaaa-bbbb-cccc", {"affected": [{"package": {"name": "x"}}]})
        assert cache.get("GHSA-aaaa-bbbb-cccc") == {"affected": [{"package": {"name": "x"}}]}

    def test_an_expired_entry_is_a_miss(self, tmp_path: Path) -> None:
        cache = JsonCache(tmp_path, "osv", ttl_days=0.0)
        cache.put("k", {"x": 1})
        assert cache.get("k") is None

    def test_an_empty_body_is_cached_as_a_negative_result(self, tmp_path: Path) -> None:
        """A 404 is cached as `{}` so a known-absent advisory is not refetched."""
        cache = JsonCache(tmp_path, "osv")
        cache.put("GHSA-absent", {})
        assert cache.get("GHSA-absent") == {}
