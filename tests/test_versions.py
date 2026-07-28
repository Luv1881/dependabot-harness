from __future__ import annotations

import pytest

from harness.versions import (
    VersionError,
    at_or_above,
    is_patch_level_bump,
    parse,
    try_parse,
)


class TestParse:
    @pytest.mark.parametrize(
        ("raw", "release"),
        [
            ("1.2.3", (1, 2, 3)),
            ("v1.2.3", (1, 2, 3)),
            ("V2.0", (2, 0)),
            ("1.2.3.4", (1, 2, 3, 4)),
            ("0.3.1", (0, 3, 1)),
            ("1:2.3.4", (2, 3, 4)),
            ("1.2.3+build.5", (1, 2, 3)),
        ],
    )
    def test_release_components(self, raw: str, release: tuple[int, ...]) -> None:
        assert parse(raw).release == release

    def test_prerelease_detected(self) -> None:
        version = parse("1.2.3-rc.1")
        assert version.is_prerelease
        assert version.prerelease == ("rc", 1)

    @pytest.mark.parametrize("raw", ["", "   ", "not-a-version"])
    def test_unparsable_raises(self, raw: str) -> None:
        with pytest.raises(VersionError):
            parse(raw)

    def test_try_parse_swallows(self) -> None:
        assert try_parse("garbage") is None
        assert try_parse(None) is None


class TestOrdering:
    @pytest.mark.parametrize(
        ("lower", "higher"),
        [
            ("1.2.3", "1.2.4"),
            ("1.2.3", "1.3.0"),
            ("1.9.0", "2.0.0"),
            ("1.2.3-rc.1", "1.2.3"),
            ("1.2.3-alpha", "1.2.3-beta"),
            ("1.2.3-rc.1", "1.2.3-rc.2"),
            ("1.2", "1.2.1"),
        ],
    )
    def test_strict_ordering(self, lower: str, higher: str) -> None:
        assert parse(lower) < parse(higher)

    def test_zero_padding_equivalence(self) -> None:
        assert parse("1.2") == parse("1.2.0")
        assert parse("1.2.0.0") == parse("1.2")

    def test_prerelease_sorts_below_release(self) -> None:
        assert parse("2.0.0-rc.1") < parse("2.0.0")


class TestAtOrAbove:
    def test_true_when_equal_or_greater(self) -> None:
        assert at_or_above("1.2.3", "1.2.3") is True
        assert at_or_above("1.3.0", "1.2.3") is True

    def test_false_when_below(self) -> None:
        assert at_or_above("1.2.2", "1.2.3") is False

    def test_none_when_undecidable(self) -> None:
        assert at_or_above(None, "1.2.3") is None
        assert at_or_above("1.2.3", None) is None
        assert at_or_above("garbage", "1.2.3") is None


class TestPatchLevelBump:
    def test_patch_bump(self) -> None:
        assert is_patch_level_bump("0.3.1", "0.3.4") is True

    def test_minor_bump_is_not_patch(self) -> None:
        assert is_patch_level_bump("0.3.1", "0.4.0") is False

    def test_major_bump_is_not_patch(self) -> None:
        assert is_patch_level_bump("1.3.1", "2.0.0") is False

    def test_already_at_or_above_is_not_a_bump(self) -> None:
        assert is_patch_level_bump("0.3.4", "0.3.4") is False
        assert is_patch_level_bump("0.3.5", "0.3.4") is False

    def test_undecidable_is_none(self) -> None:
        assert is_patch_level_bump(None, "0.3.4") is None
        assert is_patch_level_bump("garbage", "0.3.4") is None
