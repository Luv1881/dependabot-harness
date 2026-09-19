"""Deterministic policy layer: rules, engine, and the facts they consult."""

from .context import OutcomeKind, RepoFacts, RuleContext, RuleOutcome, SupersedingFix
from .engine import (
    CONFIDENCE_WHEN_ECOSYSTEM_UNKNOWN,
    ClearanceStats,
    PolicyEngine,
    PolicyError,
    policy_confidence,
)
from .facts import RepoFactsProvider
from .rules import RULE_TYPES, Rule

__all__ = [
    "CONFIDENCE_WHEN_ECOSYSTEM_UNKNOWN",
    "RULE_TYPES",
    "ClearanceStats",
    "OutcomeKind",
    "PolicyEngine",
    "PolicyError",
    "RepoFacts",
    "RepoFactsProvider",
    "Rule",
    "RuleContext",
    "RuleOutcome",
    "SupersedingFix",
    "policy_confidence",
]
