"""Deterministic policy layer: rules, engine, and the facts they consult."""

from .context import OutcomeKind, RepoFacts, RuleContext, RuleOutcome
from .engine import ClearanceStats, PolicyEngine, PolicyError
from .facts import RepoFactsProvider
from .rules import RULE_TYPES, Rule

__all__ = [
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
]
