from __future__ import annotations

import random

import pytest

from harness.util import (
    RetryExhausted,
    alert_key,
    canonical_json,
    matches_any,
    purl_package_name,
    retry_with_backoff,
    sha256_hex,
)


class TestAlertKey:
    """alert_key is the dedup and cache anchor — instability here breaks every metric."""

    def test_stable_across_calls(self) -> None:
        args = dict(
            ghsa_id="GHSA-aaaa-bbbb-cccc",
            purl="pkg:golang/example.com/x",
            resolved_version="1.2.3",
            manifest_path="go.mod",
            repo="org/repo",
        )
        assert alert_key(**args) == alert_key(**args)  # type: ignore[arg-type]

    def test_manifest_path_disambiguates_monorepo(self) -> None:
        """§14.4 — one repo, many manifests must produce distinct keys."""
        base = dict(
            ghsa_id="GHSA-aaaa-bbbb-cccc",
            purl="pkg:npm/lodash",
            resolved_version="4.17.20",
            repo="org/monorepo",
        )
        a = alert_key(manifest_path="services/api/package.json", **base)  # type: ignore[arg-type]
        b = alert_key(manifest_path="services/web/package.json", **base)  # type: ignore[arg-type]
        assert a != b

    def test_missing_resolved_version_is_not_the_string_none(self) -> None:
        with_none = alert_key(
            ghsa_id="G", purl="p", resolved_version=None, manifest_path="m", repo="r"
        )
        with_empty = alert_key(
            ghsa_id="G", purl="p", resolved_version="", manifest_path="m", repo="r"
        )
        assert with_none == with_empty
        assert "None" not in sha256_hex("G", "p", "", "m", "r")

    def test_field_order_matters(self) -> None:
        assert sha256_hex("a", "b") != sha256_hex("b", "a")


class TestCanonicalJson:
    def test_key_order_irrelevant(self) -> None:
        assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})

    def test_no_incidental_whitespace(self) -> None:
        assert canonical_json({"a": 1}) == '{"a":1}'


class TestMatchesAny:
    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            ("go.mod", "**/go.mod"),
            ("services/api/go.mod", "**/go.mod"),
            ("package.json", "**/package.json"),
            ("infra/main.tf", "**/*.tf"),
            ("routes/index.go", "**/routes/**"),
            ("cmd/api/routes/v1.go", "**/routes/**"),
            ("requirements-dev.txt", "**/requirements*.txt"),
        ],
    )
    def test_matches(self, path: str, pattern: str) -> None:
        assert matches_any(path, [pattern])

    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            ("go.sum", "**/go.mod"),
            ("src/main.py", "**/*.tf"),
            ("router/index.go", "**/routes/**"),
        ],
    )
    def test_does_not_match(self, path: str, pattern: str) -> None:
        assert not matches_any(path, [pattern])


class TestRetry:
    def test_returns_on_first_success(self) -> None:
        calls = []

        def fn() -> str:
            calls.append(1)
            return "ok"

        assert retry_with_backoff(fn, sleep=lambda _: None) == "ok"
        assert len(calls) == 1

    def test_retries_then_succeeds(self) -> None:
        attempts = {"n": 0}

        def fn() -> str:
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise ValueError("transient")
            return "ok"

        result = retry_with_backoff(
            fn, attempts=5, sleep=lambda _: None, rng=random.Random(0)
        )
        assert result == "ok"
        assert attempts["n"] == 3

    def test_exhaustion_raises_and_chains_cause(self) -> None:
        def fn() -> str:
            raise ValueError("always")

        with pytest.raises(RetryExhausted) as exc:
            retry_with_backoff(fn, attempts=3, sleep=lambda _: None)
        assert isinstance(exc.value.__cause__, ValueError)

    def test_delay_is_bounded_and_jittered(self) -> None:
        delays: list[float] = []

        def fn() -> str:
            raise ValueError("x")

        with pytest.raises(RetryExhausted):
            retry_with_backoff(
                fn,
                attempts=6,
                base_delay=1.0,
                max_delay=10.0,
                sleep=delays.append,
                rng=random.Random(1),
            )
        assert all(0 <= d <= 10.0 for d in delays)
        assert len(set(delays)) > 1


class TestRetryIfNarrowsRetryability:
    """`retry_on` selects by type; `retry_if` lets an error that carries its own verdict
    opt out. Without it every `ModelError` retries, including permanent ones."""

    def test_a_rejected_error_is_raised_unchanged_and_not_retried(self) -> None:
        calls = 0

        def fn() -> str:
            nonlocal calls
            calls += 1
            raise ValueError("permanent")

        with pytest.raises(ValueError, match="permanent"):
            retry_with_backoff(
                fn,
                attempts=5,
                retry_on=(ValueError,),
                retry_if=lambda exc: exc.args[0] != "permanent",
                sleep=lambda _: None,
            )
        assert calls == 1

    def test_an_accepted_error_still_retries(self) -> None:
        calls = 0

        def fn() -> str:
            nonlocal calls
            calls += 1
            raise ValueError("transient")

        with pytest.raises(RetryExhausted):
            retry_with_backoff(
                fn,
                attempts=3,
                retry_on=(ValueError,),
                retry_if=lambda exc: exc.args[0] != "permanent",
                sleep=lambda _: None,
            )
        assert calls == 3

    def test_the_rejected_error_keeps_its_own_type_not_retry_exhausted(self) -> None:
        """A permanent failure reported as `RetryExhausted` names nothing an operator can act on."""

        class ConfigError(Exception):
            pass

        def fn() -> str:
            raise ConfigError("set ANTHROPIC_API_KEY")

        with pytest.raises(ConfigError, match="set ANTHROPIC_API_KEY"):
            retry_with_backoff(
                fn,
                attempts=3,
                retry_on=(ConfigError,),
                retry_if=lambda _: False,
                sleep=lambda _: None,
            )


class TestPurlPackageName:
    """A coordinate that still carries a version matches no import, and a rule that reads
    'matches no import' as 'never imported' would clear a live vulnerability."""

    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            ("pkg:npm/lodash", "lodash"),
            ("pkg:npm/lodash@4.17.21", "lodash"),
            ("pkg:npm/@scope/name", "@scope/name"),
            ("pkg:npm/@scope/name@1.2.3", "@scope/name"),
            ("pkg:npm/@scope/name@1.2.3?arch=x", "@scope/name"),
            ("pkg:npm/@scope/name#sub/path", "@scope/name"),
            ("pkg:pypi/pyarrow", "pyarrow"),
            ("pkg:pypi/Flask@2.0.1", "Flask"),
            (
                "pkg:golang/github.com/prometheus/prometheus",
                "github.com/prometheus/prometheus",
            ),
            (
                "pkg:maven/com.fasterxml.core/jackson-databind",
                "com.fasterxml.core/jackson-databind",
            ),
        ],
    )
    def test_coordinate_is_extracted(self, purl: str, expected: str) -> None:
        assert purl_package_name(purl) == expected

    @pytest.mark.parametrize("purl", ["", "garbage", "pkg:npm", ":", "/only"])
    def test_a_malformed_purl_yields_nothing_rather_than_a_wrong_name(self, purl: str) -> None:
        assert purl_package_name(purl) == ""
