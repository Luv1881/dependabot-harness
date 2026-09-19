"""RepoFacts implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..analysis.imports import ImportIndex, build_scanner
from ..db import AlertRecord, Database
from ..versions import try_parse
from .context import SupersedingFix


@dataclass
class RepoFactsProvider:
    """Sources repo-level evidence from a checkout, the DB and the architecture cache.

    Import indexes are computed once per (repo, ecosystem) and reused across every alert
    in that repo.
    """

    repo: str
    db: Database
    checkout_path: Path | None = None
    architecture: dict[str, Any] | None = None
    structure_hash: str | None = None
    _indexes: dict[str, ImportIndex] = field(default_factory=dict, repr=False)

    def import_index(self, ecosystem: str) -> ImportIndex:
        if ecosystem in self._indexes:
            return self._indexes[ecosystem]
        scanner = build_scanner(ecosystem)
        if scanner is None:
            index = ImportIndex.unavailable(f"no scanner for ecosystem {ecosystem!r}")
        elif self.checkout_path is None:
            index = ImportIndex.unavailable("no checkout available")
        else:
            index = scanner.scan(self.checkout_path)
        self._indexes[ecosystem] = index
        return index

    def production_build_targets(self) -> list[str] | None:
        if not self.architecture:
            return None
        targets = self.architecture.get("build_targets")
        if not isinstance(targets, list):
            return None
        return [
            str(t.get("entry") or t.get("name"))
            for t in targets
            if isinstance(t, dict) and t.get("ships_to_prod")
        ]

    def superseding_fix_for(self, alert: AlertRecord) -> SupersedingFix | None:
        """The highest patched version among the other open advisories for this package.

        Same repo, purl and manifest, a different advisory, and a higher patch: one upgrade
        remediates this alert and that one together. Returns the version as well as the id,
        because that version is the actionable remedy and this alert's own patch is not.
        """
        mine = try_parse(alert.patched_ver)
        if mine is None:
            return None
        rows = self.db.query(
            "SELECT ghsa_id, patched_ver FROM alerts "
            "WHERE repo=? AND purl=? AND manifest_path=? AND ghsa_id!=? AND state='open' "
            "ORDER BY ghsa_id ASC",
            (alert.repo, alert.purl, alert.manifest_path, alert.ghsa_id),
        )
        candidates = [
            (parsed, str(row["ghsa_id"]), row["patched_ver"])
            for row in rows
            if (parsed := try_parse(row["patched_ver"])) is not None and parsed > mine
        ]
        if not candidates:
            return None
        _version, ghsa_id, patched = max(candidates, key=lambda triple: (triple[0], triple[1]))
        return SupersedingFix(ghsa_id=ghsa_id, patched_version=str(patched) if patched else None)
