from __future__ import annotations

import pytest

from harness.cvss import parse_vector, severity_label


class TestPublishedReferenceVectors:
    """Scores checked against the published CVSS v3.1 examples."""

    @pytest.mark.parametrize(
        ("vector", "expected"),
        [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ],
    )
    def test_base_score(self, vector: str, expected: float) -> None:
        result = parse_vector(vector)
        assert result is not None
        assert result.base == pytest.approx(expected)

    def test_v30_vectors_are_accepted(self) -> None:
        result = parse_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result is not None
        assert result.base == pytest.approx(9.8)


class TestUnscorable:
    @pytest.mark.parametrize(
        "vector",
        [None, "", "garbage", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:N"],
    )
    def test_unparsable_is_none_not_zero(self, vector: str | None) -> None:
        """An unscored advisory is unscored. Zero would read as 'harmless'."""
        assert parse_vector(vector) is None

    def test_unknown_metric_value_is_none(self) -> None:
        assert parse_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


class TestSeverityLabel:
    @pytest.mark.parametrize(
        ("score", "label"),
        [
            (0.0, "none"),
            (0.1, "low"),
            (3.9, "low"),
            (4.0, "medium"),
            (6.9, "medium"),
            (7.0, "high"),
            (8.9, "high"),
            (9.0, "critical"),
            (10.0, "critical"),
        ],
    )
    def test_bands(self, score: float, label: str) -> None:
        assert severity_label(score) == label

    def test_critical_threshold_matches_the_kev_rule(self) -> None:
        """The kev_direct_critical rule fires at 9.0; the label must agree."""
        assert severity_label(9.0) == "critical"
        assert severity_label(8.9) != "critical"


class TestScoresFeedTheKevRule:
    def test_a_scored_vector_can_trip_the_critical_threshold(self) -> None:
        result = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result is not None
        assert result.base >= 9.0
