from __future__ import annotations

from typing import ClassVar

import pytest

from harness.cvss import parse_vector, severity_label


class TestAgainstTheReferenceImplementation:
    """Differential test against the `cvss` library over the whole metric space.

    Hand-copied expected scores are the thing most likely to be wrong here, so the
    oracle is an independent implementation rather than a table of remembered constants.
    """

    METRICS: ClassVar = {
        "AV": "NALP",
        "AC": "LH",
        "PR": "NLH",
        "UI": "NR",
        "S": "UC",
        "C": "HLN",
        "I": "HLN",
        "A": "HLN",
    }

    def all_vectors(self) -> list[str]:
        from itertools import product

        keys = list(self.METRICS)
        return [
            "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in zip(keys, combo, strict=True))
            for combo in product(*self.METRICS.values())
        ]

    def test_every_vector_in_the_metric_space_matches(self) -> None:
        cvss_lib = pytest.importorskip("cvss")

        vectors = self.all_vectors()
        assert len(vectors) == 4 * 2 * 3 * 2 * 2 * 3 * 3 * 3

        mismatches = [
            v
            for v in vectors
            if abs(float(cvss_lib.CVSS3(v).base_score) - parse_vector(v).base) > 1e-9
        ]
        assert mismatches == []

    def test_roundup_ceilings_rather_than_rounding_half_up(self) -> None:
        """CVSS v3.1 Appendix A changed this from v3.0; half-up disagrees with the spec."""
        from harness.cvss import _round_up

        assert _round_up(7.14) == 7.2
        assert _round_up(7.10) == 7.1
        assert _round_up(0.0) == 0.0

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
