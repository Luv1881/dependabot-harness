"""Provider-agnostic model access.

This is the only module permitted to import a provider SDK, and no provider type leaves
it. Everything downstream sees :class:`ModelRequest` and :class:`ModelResponse`.

The client owns three guarantees:

- no request exceeds the role's 25% context ceiling
- every call is ledgered before its result is returned
- a response body carrying a provider error is a failure, whatever the status code said
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from typing import Any

from ..config import ModelConfig
from ..util import retry_with_backoff
from .budget import BudgetLedger, Usage, is_priced
from .errors import (
    Classification,
    ModelError,
    ProviderConfigurationError,
    ResponseClass,
    classify,
    is_permanent_provider_error,
)

log = logging.getLogger(__name__)

CHARS_PER_TOKEN = 3


class ContextCeilingExceeded(ValueError):
    """Assembled context exceeds the role's share of the model window."""


@dataclass
class ModelRequest:
    system: str
    user: str
    max_tokens: int = 8000
    cacheable_prefix: str = ""
    tools: list[dict[str, Any]] = field(default_factory=list)
    effort: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)

    def messages(self) -> list[dict[str, Any]]:
        """The full conversation: the opening turn plus any tool round-trips."""
        return [{"role": "user", "content": self.user}, *self.history]

    def estimated_tokens(self) -> int:
        """Character-based estimate, used only to enforce the ceiling before a call.

        Deliberately pessimistic. Over-estimating tokens tightens the ceiling and costs
        an occasional avoidable rejection; under-estimating lets an oversized request
        through, which is the failure the ceiling exists to prevent.
        """
        chars = len(self.system) + len(self.user) + len(self.cacheable_prefix)
        chars += sum(len(json.dumps(t)) for t in self.tools)
        chars += sum(len(json.dumps(m, default=str)) for m in self.history)
        return chars // CHARS_PER_TOKEN


@dataclass
class ModelResponse:
    text: str
    usage: Usage
    stop_reason: str | None = None
    model: str = ""
    classification: Classification = field(default_factory=lambda: Classification(ResponseClass.OK))
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw_content: list[dict[str, Any]] = field(default_factory=list)
    """The assistant turn as content blocks, for replaying into a tool round-trip."""

    @property
    def is_usable(self) -> bool:
        return self.classification.is_usable

    def json(self) -> Any:
        """Parse the body as JSON, tolerating a fenced code block around it."""
        body = self.text.strip()
        if body.startswith("```"):
            body = body.split("\n", 1)[-1]
            if body.endswith("```"):
                body = body[: body.rindex("```")]
        start, end = body.find("{"), body.rfind("}")
        if start == -1 or end == -1:
            raise ModelError("response contains no JSON object", ResponseClass.MALFORMED)
        try:
            return json.loads(body[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ModelError(
                f"unparsable JSON in response: {exc}", ResponseClass.MALFORMED
            ) from exc


class ModelProvider(ABC):
    """One implementation per vendor. Constructed lazily so an unused SDK is never imported."""

    name: str

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key

    @abstractmethod
    def complete(self, request: ModelRequest, model: str) -> ModelResponse: ...


class AnthropicProvider(ModelProvider):
    name = "anthropic"

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(api_key)
        self._client: Any = None

    def _ensure_client(self) -> Any:
        if self._client is None:
            import anthropic

            self._client = (
                anthropic.Anthropic(api_key=self._api_key)
                if self._api_key
                else anthropic.Anthropic()
            )
        return self._client

    def complete(self, request: ModelRequest, model: str) -> ModelResponse:
        client = self._ensure_client()
        system: list[dict[str, Any]] = []
        if request.cacheable_prefix:
            system.append(
                {
                    "type": "text",
                    "text": request.cacheable_prefix,
                    "cache_control": {"type": "ephemeral"},
                }
            )
        if request.system:
            system.append({"type": "text", "text": request.system})

        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": request.max_tokens,
            "system": system,
            "messages": request.messages(),
        }
        if request.effort:
            kwargs["output_config"] = {"effort": request.effort}
        if request.tools:
            kwargs["tools"] = request.tools

        raw = client.messages.create(**kwargs)
        text = "".join(block.text for block in raw.content if getattr(block, "type", "") == "text")
        tool_calls = [
            {"name": b.name, "input": b.input, "id": b.id}
            for b in raw.content
            if getattr(b, "type", "") == "tool_use"
        ]
        raw_content = [_block_to_dict(b) for b in raw.content]
        usage = Usage(
            tokens_in=getattr(raw.usage, "input_tokens", 0) or 0,
            tokens_out=getattr(raw.usage, "output_tokens", 0) or 0,
            cache_read_tokens=getattr(raw.usage, "cache_read_input_tokens", 0) or 0,
            cache_write_tokens=getattr(raw.usage, "cache_creation_input_tokens", 0) or 0,
        )
        return ModelResponse(
            text=text,
            usage=usage,
            stop_reason=getattr(raw, "stop_reason", None),
            model=getattr(raw, "model", model),
            tool_calls=tool_calls,
            raw_content=raw_content,
        )


def _block_to_dict(block: Any) -> dict[str, Any]:
    kind = getattr(block, "type", "")
    if kind == "text":
        return {"type": "text", "text": block.text}
    if kind == "tool_use":
        return {"type": "tool_use", "id": block.id, "name": block.name, "input": block.input}
    return {"type": kind}


class OpenAICompatibleProvider(ModelProvider):
    """A vendor whose API speaks the OpenAI chat-completions wire format.

    DeepSeek differs from OpenAI in base URL and credential and in nothing else the
    harness relies on, so the two share one implementation and one response parser
    rather than a copy that drifts. A vendor with its own wire format (Anthropic) is a
    separate :class:`ModelProvider`; this class is only for the compatible ones.
    """

    base_url: str | None = None
    """None means the SDK's own default, which is what OpenAI itself wants."""

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(api_key)
        self._client: Any = None

    def _ensure_client(self) -> Any:
        if self._client is None:
            import openai

            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = openai.OpenAI(**kwargs)
        return self._client

    def complete(self, request: ModelRequest, model: str) -> ModelResponse:
        client = self._ensure_client()
        messages: list[dict[str, Any]] = []
        if request.cacheable_prefix or request.system:
            messages.append(
                {
                    "role": "system",
                    "content": f"{request.cacheable_prefix}\n\n{request.system}".strip(),
                }
            )
        messages.extend(_openai_messages(request))

        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": request.max_tokens,
            "messages": messages,
        }
        if request.tools:
            kwargs["tools"] = _openai_tools(request.tools)

        raw = client.chat.completions.create(**kwargs)
        choice = raw.choices[0]
        usage = Usage(
            tokens_in=getattr(raw.usage, "prompt_tokens", 0) or 0,
            tokens_out=getattr(raw.usage, "completion_tokens", 0) or 0,
        )
        return ModelResponse(
            text=choice.message.content or "",
            usage=usage,
            stop_reason=_neutral_stop_reason(getattr(choice, "finish_reason", None)),
            model=getattr(raw, "model", model),
            tool_calls=_tool_calls(choice.message),
            raw_content=_neutral_blocks(choice.message),
        )


_STOP_REASONS = {
    "length": "max_tokens",
    "content_filter": "refusal",
}
"""OpenAI-shaped vocabulary translated to the neutral one `classify` reads.

Without this a truncated completion arrives as `finish_reason='length'`, which matches
none of the neutral values, and is therefore classified as a complete, usable answer. The
truncated-and-retried path exists precisely so a clipped response is not mistaken for a
finished one.
"""


def _neutral_stop_reason(finish_reason: Any) -> str | None:
    if finish_reason is None:
        return None
    text = str(finish_reason)
    return _STOP_REASONS.get(text, text)


def _neutral_blocks(message: Any) -> list[dict[str, Any]]:
    """The assistant turn in the neutral shape the tool loop replays.

    Anthropic returns content blocks natively; the compatible vendors do not. Producing
the same shape here keeps one history format and one translation point, rather than two
formats the loop would have to tell apart.
    """
    blocks: list[dict[str, Any]] = []
    if getattr(message, "content", None):
        blocks.append({"type": "text", "text": message.content})
    for call in getattr(message, "tool_calls", None) or []:
        function = getattr(call, "function", None)
        blocks.append(
            {
                "type": "tool_use",
                "id": getattr(call, "id", ""),
                "name": getattr(function, "name", ""),
                "input": _tool_arguments(getattr(function, "arguments", None)),
            }
        )
    return blocks


def _tool_calls(message: Any) -> list[dict[str, Any]]:
    return [block for block in _neutral_blocks(message) if block["type"] == "tool_use"]


def _tool_arguments(raw: Any) -> dict[str, Any]:
    """A tool call's arguments, which arrive as a JSON-encoded string.

    Unparsable arguments become an empty mapping rather than an exception. The tool then
    reports a missing argument back to the model, which can correct itself; raising here
    would discard the whole turn over one malformed field.
    """
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        log.warning("tool call arrived with unparsable arguments; treating as empty")
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Translate the neutral (Anthropic-shaped) tool declarations to OpenAI's."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
            },
        }
        for tool in tools
    ]


def _openai_messages(request: ModelRequest) -> list[dict[str, Any]]:
    """Neutral conversation to OpenAI's wire format, tool round-trips included."""
    out: list[dict[str, Any]] = []
    for message in request.messages():
        role = message.get("role")
        content = message.get("content")
        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue
        if not isinstance(content, list):
            continue
        if role == "assistant":
            out.extend(_openai_assistant_turn(content))
        else:
            out.extend(_openai_tool_results(content))
    return out


def _openai_assistant_turn(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One assistant message, carrying text and any tool calls together.

    Emitting them separately would produce two consecutive assistant turns, which the API
    rejects and which would also lose the association between a call and the text that
    motivated it.
    """
    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    calls = [
        {
            "id": b.get("id", ""),
            "type": "function",
            "function": {
                "name": b.get("name", ""),
                "arguments": json.dumps(b.get("input") or {}),
            },
        }
        for b in blocks
        if b.get("type") == "tool_use"
    ]
    if not text and not calls:
        return []
    message: dict[str, Any] = {"role": "assistant", "content": text or None}
    if calls:
        message["tool_calls"] = calls
    return [message]


def _openai_tool_results(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One `tool` message per result: OpenAI keys results by call id, not by position."""
    return [
        {
            "role": "tool",
            "tool_call_id": b.get("tool_use_id", ""),
            "content": str(b.get("content", "")),
        }
        for b in blocks
        if b.get("type") == "tool_result"
    ]


class OpenAIProvider(OpenAICompatibleProvider):
    name = "openai"


class DeepSeekProvider(OpenAICompatibleProvider):
    """DeepSeek's public API. OpenAI-compatible, so only the endpoint differs.

    The credential is ``DEEPSEEK_API_KEY`` and is never allowed to fall back to
    ``OPENAI_API_KEY``: pointing an OpenAI key at a third-party endpoint, or the reverse,
    is the kind of silent misroute that is only noticed on the invoice.
    """

    name = "deepseek"
    base_url = "https://api.deepseek.com/v1"


PROVIDERS: dict[str, type[ModelProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "deepseek": DeepSeekProvider,
}

PROVIDER_API_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
}
"""The environment variable each provider reads its key from.

Resolved explicitly rather than left to the SDK's own lookup so that a missing key is
reported once, by name, at construction instead of surfacing as a retried 401 deep
inside an agent loop.
"""


def required_api_key_env(name: str) -> str | None:
    """The env var a provider needs, or None when it needs no credential."""
    return PROVIDER_API_KEY_ENV.get(name)


def build_provider(name: str) -> ModelProvider:
    """Construct a provider, failing fast when its credential is absent."""
    try:
        provider_cls = PROVIDERS[name]
    except KeyError as exc:
        raise ValueError(f"unknown model provider {name!r}") from exc

    env_var = PROVIDER_API_KEY_ENV.get(name)
    if env_var is None:
        return provider_cls()
    api_key = os.environ.get(env_var)
    if not api_key:
        raise ProviderConfigurationError(
            f"model provider {name!r} requires an API key: set {env_var} in the "
            "environment before running the agent stages"
        )
    return provider_cls(api_key=api_key)


class ModelClient:
    """One configured role. Enforces the ceiling, ledgers the spend, classifies the body."""

    def __init__(
        self,
        cfg: ModelConfig,
        ledger: BudgetLedger,
        *,
        provider: ModelProvider | None = None,
        max_attempts: int = 3,
    ) -> None:
        self.cfg = cfg
        self.ledger = ledger
        self.provider = provider or build_provider(cfg.provider)
        self.max_attempts = max_attempts

    def complete(
        self,
        request: ModelRequest,
        *,
        repo: str,
        stage: str,
        alert_key: str | None = None,
    ) -> ModelResponse:
        request = self._clamp_max_tokens(request)
        self._enforce_ceiling(request)

        def once() -> ModelResponse:
            try:
                response = self.provider.complete(request, self.cfg.model)
            except ModelError:
                raise
            except Exception as exc:
                raise self._classify_provider_exception(exc) from exc
            response.classification = classify(
                response.text,
                stop_reason=response.stop_reason,
                has_tool_calls=bool(response.tool_calls),
            )
            self.ledger.record(
                repo=repo,
                stage=stage,
                model=self.cfg.model,
                usage=response.usage,
                alert_key=alert_key,
                rates=self.cfg.pricing,
            )
            if not response.is_usable:
                raise ModelError(
                    f"{self.cfg.role}: {response.classification.detail}",
                    response.classification.kind,
                )
            return response

        return retry_with_backoff(
            once,
            attempts=self.max_attempts,
            retry_on=(ModelError,),
            retry_if=lambda exc: getattr(exc, "is_retryable", True),
            on_retry=lambda attempt, delay, exc: log.warning(
                "%s retry %d after %.1fs: %s", self.cfg.role, attempt, delay, exc
            ),
        )

    def _classify_provider_exception(self, exc: BaseException) -> ModelError:
        """Turn a raw SDK exception into the retryability it actually has.

        The two cases are genuinely different failures and must not be collapsed. A
        dropped connection is worth three attempts; an unset key, a rejected key, or an
        SDK that is not installed will fail identically every time, and retrying turns a
        one-line configuration error into a `RetryExhausted` that names nothing.
        """
        if is_permanent_provider_error(exc):
            hint = ""
            if isinstance(exc, ImportError):
                hint = f"; install it with `pip install {self.cfg.provider}`"
            return ProviderConfigurationError(
                f"{self.cfg.role}: provider {self.cfg.provider!r} is not usable: "
                f"{type(exc).__name__}: {exc}{hint}"
            )
        return ModelError(
            f"{self.cfg.role}: provider call raised {type(exc).__name__}: {exc}",
            ResponseClass.TRANSIENT,
        )

    def _clamp_max_tokens(self, request: ModelRequest) -> ModelRequest:
        """Hold the requested output size inside what this model actually accepts.

        Each stage asks for what its job needs, and that number was chosen against one
        vendor's limits. A model with a lower output cap rejects the call outright, so the
        configured ceiling wins and the stage is spared a per-provider branch. The copy is
        deliberate: the caller keeps its own request object, and the tool loop still
        appends to the original history list.
        """
        ceiling = self.cfg.max_output_tokens
        if ceiling is None or request.max_tokens <= ceiling:
            return request
        return replace(request, max_tokens=ceiling)

    def _enforce_ceiling(self, request: ModelRequest) -> None:
        estimated = request.estimated_tokens()
        ceiling = self.cfg.max_context_tokens
        if estimated > ceiling:
            raise ContextCeilingExceeded(
                f"{self.cfg.role}: assembled context is ~{estimated} tokens, above the "
                f"{int(self.cfg.max_context_fraction * 100)}% ceiling of {ceiling}; "
                "assemble less context rather than raising the cap"
            )

    @property
    def unpriced(self) -> bool:
        """Whether this role's cost cannot be computed, which disarms the budget caps."""
        return not is_priced(self.cfg.model, self.cfg.pricing)
