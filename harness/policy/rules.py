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
    def evaluate(self, ctx: RuleContext) -> RuleOutcome | None:
        superseding = ctx.facts.newer_advisory_for(ctx.alert)
        if not superseding:
            return None
        return self._outcome(self.spec, detail={"superseded_by": superseding})


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

    Declines whenever the scan did not run, the ecosystem has no scanner, or the
    scanner cannot map a package coordinate onto the identifiers it emits. In each of
    those cases absence from the index is unmeasured, not proven.
    """

    def evaluate(self, ctx: RuleContext) -> RuleOutcome | None:
        scanner = build_scanner(ctx.ecosystem)
        if scanner is None or not scanner.supports_package_membership:
            return None
        index = ctx.facts.import_index(ctx.ecosystem)
        if not index.scanned:
            return None
        package = scanner.normalize_package(_package_name(ctx.alert.purl))
        if index.any_prefix(package) is not False:
            return None
        return self._outcome(
            self.spec,
            detail={"package": package, "files_scanned": index.files_scanned},
        )


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


def _package_name(purl: str) -> str:
    body = purl.split(":", 1)[1] if ":" in purl else purl
    return body.split("/", 1)[1] if "/" in body else body
