"""Model response classification.

The failure this module exists for: a transient provider error arriving as *text inside a
200 OK*. To an orchestrator that only inspects exception types, that looks like a clean
completion, and empty runs get logged as successes.

So the response body is classified, not just the exception type.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ResponseClass(StrEnum):
    OK = "ok"
    EMPTY = "empty"
    TRANSIENT = "transient"
    REFUSAL = "refusal"
    TRUNCATED = "truncated"
    MALFORMED = "malformed"

    @property
    def is_retryable(self) -> bool:
        return self in {ResponseClass.TRANSIENT, ResponseClass.EMPTY, ResponseClass.TRUNCATED}

    @property
    def is_usable(self) -> bool:
        return self is ResponseClass.OK


_ERROR_BODY_PATTERNS = (
    re.compile(r"\boverloaded_error\b", re.IGNORECASE),
    re.compile(r"\brate[_ ]limit(ed|_error)?\b", re.IGNORECASE),
    re.compile(r"\binternal server error\b", re.IGNORECASE),
    re.compile(r"\bservice unavailable\b", re.IGNORECASE),
    re.compile(r"\bbad gateway\b", re.IGNORECASE),
    re.compile(r"\bgateway time-?out\b", re.IGNORECASE),
    re.compile(r"\bupstream connect error\b", re.IGNORECASE),
    re.compile(r"\btemporarily unavailable\b", re.IGNORECASE),
)

_MARKUP_PATTERN = re.compile(r"^\s*<(!doctype|html)\b", re.IGNORECASE)

_SHORT_BODY_CHARS = 200

_ERROR_JSON_KEYS = ("error", "errors")
_TRANSIENT_TYPES = frozenset(
    {
        "overloaded_error",
        "rate_limit_error",
        "api_error",
        "timeout_error",
        "server_error",
        "internal_error",
    }
)


class ModelError(RuntimeError):
    """A model call could not produce a usable response."""

    def __init__(self, message: str, classification: ResponseClass) -> None:
        super().__init__(message)
        self.classification = classification

    @property
    def is_retryable(self) -> bool:
        return self.classification.is_retryable


@dataclass(frozen=True)
class Classification:
    kind: ResponseClass
    detail: str = ""

    @property
    def is_usable(self) -> bool:
        return self.kind.is_usable

    @property
    def is_retryable(self) -> bool:
        return self.kind.is_retryable


def classify(
    text: str | None, *, stop_reason: str | None = None, has_tool_calls: bool = False
) -> Classification:
    """Classify a completion body.

    ``stop_reason`` is advisory. A provider that has degraded into returning an error
    page will happily report a normal stop reason alongside it, which is exactly why the
    body is inspected too.

    Prose is not scanned for error keywords. An agent legitimately describing a service
    that "enforces a rate limit" or "returns Internal Server Error on bad input" is
    reporting a finding, not failing, and retrying it three times would burn budget and
    then discard a correct answer. Keyword matching is therefore confined to short
    non-JSON bodies. A provider error body is only the error; anything longer is a
    completion that happens to mention one.
    """
    if stop_reason == "refusal":
        return Classification(ResponseClass.REFUSAL, "provider refused the request")

    if text is None or not text.strip():
        if has_tool_calls:
            return Classification(ResponseClass.OK, "tool call with no accompanying text")
        return Classification(ResponseClass.EMPTY, "empty completion body")

    body = text.strip()

    parsed = _as_json_object(body)
    if parsed is not None:
        embedded = _transient_from_json(parsed)
        if embedded is not None:
            return Classification(ResponseClass.TRANSIENT, embedded)
        if stop_reason == "max_tokens":
            return Classification(ResponseClass.TRUNCATED, "hit max_tokens")
        return Classification(ResponseClass.OK)

    if _MARKUP_PATTERN.match(body):
        return Classification(ResponseClass.TRANSIENT, "markup where a completion was expected")

    if len(body) <= _SHORT_BODY_CHARS:
        for pattern in _ERROR_BODY_PATTERNS:
            match = pattern.search(body)
            if match:
                return Classification(
                    ResponseClass.TRANSIENT,
                    f"error text in a successful response: {match.group(0)!r}",
                )

    if stop_reason == "max_tokens":
        return Classification(ResponseClass.TRUNCATED, "hit max_tokens")

    return Classification(ResponseClass.OK)


def _as_json_object(body: str) -> dict[str, Any] | None:
    """Parse the body as a JSON object, or None when it is prose."""
    if not body.startswith("{"):
        return None
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _transient_from_json(parsed: dict[str, Any]) -> str | None:
    """Detect a provider error object serialized into the completion body."""
    for key in _ERROR_JSON_KEYS:
        node = parsed.get(key)
        if isinstance(node, dict):
            error_type = str(node.get("type", "")).lower()
            if error_type in _TRANSIENT_TYPES or error_type.endswith("_error"):
                return f"provider error object in body: {error_type or 'unknown'}"
            return f"provider error object in body: {node.get('message', 'unknown')}"
        if isinstance(node, list) and node:
            return "provider error array in body"
    return None


def classify_payload(payload: dict[str, Any]) -> Classification:
    """Classify a raw provider payload that was returned with a success status."""
    if payload.get("type") == "error" or "error" in payload:
        return Classification(ResponseClass.TRANSIENT, "error payload under a success status")
    return Classification(ResponseClass.OK)
