"""Deterministic candidate shortlisting.

Inverted indexes over ghsa_id, (purl, major), the affected symbol set, and manifest path.
All-pairs comparison is O(N squared) and does not survive fleet scale, so a model never
sees more than a bounded shortlist per alert.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..db import AlertRecord
from ..versions import try_parse

MAX_SHORTLIST = 10


@dataclass
class InvertedIndex:
    by_ghsa: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    by_purl_major: dict[tuple[str, int], list[str]] = field(
        default_factory=lambda: defaultdict(list)
    )
    by_symbol: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    by_manifest: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    alerts: dict[str, AlertRecord] = field(default_factory=dict)

    @classmethod
    def build(cls, alerts: list[AlertRecord]) -> InvertedIndex:
        index = cls()
        for alert in alerts:
            key = alert.alert_key
            index.alerts[key] = alert
            index.by_ghsa[alert.ghsa_id].append(key)
            index.by_purl_major[(alert.purl, _major(alert))].append(key)
            index.by_manifest[(alert.repo, alert.manifest_path)].append(key)
            for symbol in alert.symbols or []:
                index.by_symbol[symbol].append(key)
        return index

    def candidates(self, alert: AlertRecord, *, limit: int = MAX_SHORTLIST) -> list[str]:
        """Up to ``limit`` alerts that plausibly share a fix with this one.

        Scored so that the strongest signal survives truncation: a shared advisory beats
        a shared major version, which beats a shared symbol, which beats a shared
        manifest.
        """
        scores: dict[str, int] = defaultdict(int)
        for key in self.by_ghsa.get(alert.ghsa_id, []):
            scores[key] += 8
        for key in self.by_purl_major.get((alert.purl, _major(alert)), []):
            scores[key] += 4
        for symbol in alert.symbols or []:
            for key in self.by_symbol.get(symbol, []):
                scores[key] += 2
        for key in self.by_manifest.get((alert.repo, alert.manifest_path), []):
            scores[key] += 1

        scores.pop(alert.alert_key, None)
        ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        return [key for key, _score in ranked[:limit]]

    def comparisons_avoided(self) -> tuple[int, int]:
        """(all-pairs, shortlisted) comparison counts, for the M9 accept metric."""
        total = len(self.alerts)
        all_pairs = total * (total - 1) // 2
        shortlisted = sum(len(self.candidates(a)) for a in self.alerts.values()) // 2
        return all_pairs, shortlisted


@dataclass(frozen=True)
class Cluster:
    cluster_id: str
    canonical: str
    members: tuple[str, ...]
    rationale: str = ""

    @property
    def non_canonical(self) -> tuple[str, ...]:
        return tuple(m for m in self.members if m != self.canonical)


def trivial_clusters(index: InvertedIndex) -> list[Cluster]:
    """Clusters no model is needed for: one identical upgrade closes all of them.

    Keyed on the advisory, the package, the major version in use, and the target version.
    The same advisory against the same package at 1.x and 2.x is two different upgrade
    paths with different reachability, and clustering them would make one alert inherit a
    verdict reasoned about for the other.
    """
    groups: dict[tuple[str, str, int, str], list[str]] = defaultdict(list)
    for key, alert in index.alerts.items():
        groups[(alert.ghsa_id, alert.purl, _major(alert), alert.patched_ver or "")].append(key)

    clusters: list[Cluster] = []
    for (ghsa, purl, major, patched), members in sorted(groups.items()):
        if len(members) < 2:
            continue
        ordered = sorted(members)
        clusters.append(
            Cluster(
                cluster_id=f"{ghsa}:{purl}:{major}:{patched}",
                canonical=_pick_canonical(index, ordered),
                members=tuple(ordered),
                rationale=(
                    f"same advisory and package on the {major}.x line; "
                    f"one bump to {patched or 'the patched version'} closes all"
                ),
            )
        )
    return clusters


def _pick_canonical(index: InvertedIndex, members: list[str]) -> str:
    """The alert whose verdict the others inherit.

    Prefers a direct dependency with the highest CVSS: that is the member most likely to
    be analyzed well and least likely to be dismissed for the wrong reason.
    """

    def rank(key: str) -> tuple[int, float, str]:
        alert = index.alerts[key]
        return (0 if alert.is_direct else 1, -(alert.cvss_score or 0.0), key)

    return min(members, key=rank)


def _major(alert: AlertRecord) -> int:
    version = try_parse(alert.resolved_ver)
    return version.major if version else -1
