"""Evaluation harness: golden set, metrics, and pipeline scoring."""

from .dataset import GoldenCase, GoldenSet, Label, Split, load_golden
from .metrics import EvalReport, Outcome, compare
from .runner import DeterministicPredictor, Prediction, Predictor, evaluate, summarize

__all__ = [
    "DeterministicPredictor",
    "EvalReport",
    "GoldenCase",
    "GoldenSet",
    "Label",
    "Outcome",
    "Prediction",
    "Predictor",
    "Split",
    "compare",
    "evaluate",
    "load_golden",
    "summarize",
]
