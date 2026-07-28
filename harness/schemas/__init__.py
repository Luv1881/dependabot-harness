"""JSON Schema loading and validation. Every stage boundary validates its payload."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

_DIR = Path(__file__).parent


class SchemaViolation(ValueError):
    """Payload failed schema validation. Stage 7a rejects and requeues on this."""


@cache
def _validator(name: str) -> Draft202012Validator:
    path = _DIR / f"{name}.json"
    if not path.is_file():
        raise FileNotFoundError(f"no schema named {name!r} in {_DIR}")
    return Draft202012Validator(json.loads(path.read_text()))


def validate(name: str, payload: Any) -> None:
    """Raise :class:`SchemaViolation` listing every error, not just the first."""
    errors = sorted(_validator(name).iter_errors(payload), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors)
        raise SchemaViolation(f"{name}: {detail}")


def is_valid(name: str, payload: Any) -> bool:
    return bool(_validator(name).is_valid(payload))
