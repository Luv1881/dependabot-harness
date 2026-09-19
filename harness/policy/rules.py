"""Deterministic policy rules.

Each rule is a class implementing :class:`Rule`. Adding a rule means adding a class and
registering it; the engine never changes.

Every rule returns None when it cannot decide. Silence is not a clearance: an
undecidable rule declines, and the alert flows on to the expensive stages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..analysis.imports import build_scanner
from ..ecosystems import get_adapter
from ..ecosystems.base import Scope
from ..util import purl_package_name
from ..versions import at_or_above, is_patch_level_bump
from .context import OutcomeKind, RuleContext, RuleOutcome


class Rule(ABC):
    id: str

    @abstractmethod
    def evaluate(self, ctx: RuleContext) -> RuleOutcome | None:
        """Terminating outcome, or None to decline."""

    def _outcome(self, spec: dict[str, Any], **overrides: Any) -> RuleOutcome:
        outcome = spec.get("outcome") or {}
        merged = {
            "kind": OutcomeKind(outcome.get("kind", "verdict")),
            "reason": outcome.get("reason", self.id),
            "verdict": outcome.get("verdict"),
            "vex_status": outcome.get("vex_status"),
            "vex_justification": outcome.get("vex_justification"),
            "needs_human": bool(outcome.get("needs_human", False)),
            "recommended_action": outcome.get("recommended_action"),
        }
        detail = dict(overrides.pop("detail", {}))
        merged.update(overrides)
        return RuleOutcome(rule_id=self.id, detail=detail, **merged)


class ConfiguredRule(Rule):
    """A rule whose verdict shape comes from policy.yaml, keeping data out of code."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.spec = spec
        self.id = str(spec["id"])


class AlreadyFixedRule(ConfiguredRule):
    def evaluate(self, ctx: RuleContext) -> RuleOutcome | None:
        alert = ctx.alert
        decided = at_or_above(alert.resolved_ver, alert.patched_ver)
        if decided is not True:
            return None
        return self._outcome(
            self.spec,
            detail={"resolved": alert.resolved_ver, "patched": alert.patched_ver},
        )


class SupersededRule(ConfiguredRule):
    """A newer advisory for the same package exists, so one upgrade fixes both.

    This is *not* a clearance, and treating it as one was a defect: reachability is
    per-advisory, so a newer patch that fixes a sibling CVE says nothing about whether
    this advisory's vulnerable symbol is reachable. Sharing the sibling's verdict across
    two different advisories would be a false-negative path.

    What the fact does establish is that the installed version is inside this advisory's
    affected range — the alert is open, after all — and that a single upgrade remediates
    it. So the alert is decided `affected` with that upgrade as its remedy: a real
    decision, a real VEX statement, and no reachability claim that has not been measured.
    """

    def evaluate(self, ctx: RuleContext) -> RuleOutcome | None:
        superseding = ctx.facts.superseding_fix_for(ctx.alert)
        if superseding is None:
            return None
        target = superseding.patched_version or ctx.alert.patched_ver
        return self._outcome(
            self.spec,
            detail={"superseded_by": superseding.ghsa_id, "fix_version": target},
            recommended_action=(
                f"upgrade {ctx.alert.purl} to {target or 'a patched version'}; the newer "
                f"advisory {superseding.ghsa_id} for the same package is fixed by the "
                "same upgrade"
            ),
        )


class KevDirectCriticalRule(ConfiguredRule):
    def evaluate(self, ctx: RuleContext) -> RuleOutcome | None:
        alert = ctx.alert
        threshold = float((self.spec.get("when") or {}).get("cvss_min", 9.0))
        if not alert.in_kev or alert.is_direct is not True:
            return None
        if alert.cvss_score is None or alert.cvss_score < threshold:
            return None
        return self._outcome(
            self.spec,
            detail={"cvss": alert.cvss_score, "in_kev": True, "is_direct": True},
        )


class DevOnlyRule(ConfiguredRule):
    """Dev-scope dependency absent from every production build target.

    Manifest scope alone clears the alert only where the build system structurally
    excludes that scope from the shipped artifact. Everywhere else a bundler or
    packaging step can still pull a dev-scoped dependency into production, so the claim
    needs the build targets from a cached architecture; without them the rule declines.
    """

    def evaluate(self, ctx: RuleContext) -> RuleOutcome | None:
        alert = ctx.alert
        if alert.dep_scope != Scope.DEVELOPMENT:
            return None
        targets = ctx.facts.production_build_targets()
        if targets is None:
            adapter = get_adapter(ctx.ecosystem)
            if adapter is None or not adapter.dev_scope_is_conclusive():
                return None
            return self._outcome(
                self.spec,
                reason="dev_scope_excluded_from_artifact_by_build_system",
                detail={"variant": "scope_conclusive", "scope": alert.dep_scope},
            )
        if alert.purl in targets or alert.manifest_path in targets:
            return None
        return self._outcome(
            self.spec,
            detail={"variant": "build_targets_checked", "prod_targets": len(targets)},
        )


class NotImportedRule(ConfiguredRule):
    """Package name never appears in any import statement across the repo.

    Declines whenever the scan did not run, the ecosystem has no scanner, or the scanner
    cannot map a package coordinate onto the identifiers it emits. In each of those cases
    absence from the index is unmeasured, not proven.

    It also declines when the package's code is in the *artifact*, whatever the import
    index says. The verdict carries the CISA code ``vulnerable_code_not_present``, which is
    a claim about what ships, and a package nothing imports still ships when something
    that *is* imported depends on it. On a real npm repository this rule cleared 220 alerts
    on an import index alone, and 127 of them were packages shipped inside an imported
    dependent — ``handlebars`` inside ``hbs``, ``qs`` inside ``body-parser``. Their
    vulnerable code was in the bundle.
    """

    def evaluate(self, ctx: RuleContext) -> RuleOutcome | None:
        scanner = build_scanner(ctx.ecosystem)
        if scanner is None or not scanner.supports_package_membership:
            return None
        package = scanner.normalize_package(purl_package_name(ctx.alert.purl))
        if not package:
            return None
        index = ctx.facts.import_index(ctx.ecosystem)
        if not index.scanned:
            return None
        if index.any_prefix(package) is not False:
            return None
        shipped = ctx.facts.shipped_packages(ctx.ecosystem)
        if shipped is None:
            return None
        if any(_ships_together(package, name) for name in shipped):
            return None
        return self._outcome(
            self.spec,
            detail={
                "package": package,
                "files_scanned": index.files_scanned,
                "in_artifact": False,
                "artifact_packages": len(shipped),
            },
        )


def _ships_together(package: str, shipped: str) -> bool:
    """Whether a shipped name and the alert's package put the same code in the artifact.

    Both directions matter. A subpackage of the package ships (its code is compiled in),
    and the package nested inside a shipped module ships (it is a package of that module).
    Go module and package paths share a namespace by prefix, so the relationship is only
    ever prefix containment.
    """
    if package == shipped:
        return True
    return package.startswith(f"{shipped}/") or shipped.startswith(f"{package}/")


class TrivialPatchRule(ConfiguredRule):
    def evaluate(self, ctx: RuleContext) -> RuleOutcome | None:
        alert = ctx.alert
        if is_patch_level_bump(alert.resolved_ver, alert.patched_ver) is not True:
            return None
        return self._outcome(
            self.spec,
            detail={"resolved": alert.resolved_ver, "patched": alert.patched_ver},
        )


RULE_TYPES: dict[str, type[ConfiguredRule]] = {
    "already_fixed": AlreadyFixedRule,
    "superseded": SupersededRule,
    "kev_direct_critical": KevDirectCriticalRule,
    "dev_only": DevOnlyRule,
    "not_imported": NotImportedRule,
    "trivial_patch": TrivialPatchRule,
}
