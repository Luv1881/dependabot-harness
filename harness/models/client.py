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
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..config import ModelConfig
from ..util import retry_with_backoff
from .budget import BudgetLedger, Usage, is_priced
from .errors import Classification, ModelError, ResponseClass, classify

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

    @abstractmethod
    def complete(self, request: ModelRequest, model: str) -> ModelResponse: ...


class AnthropicProvider(ModelProvider):
    name = "anthropic"

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key
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


class OpenAIProvider(ModelProvider):
    name = "openai"

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key
        self._client: Any = None

    def _ensure_client(self) -> Any:
        if self._client is None:
            import openai

            self._client = (
                openai.OpenAI(api_key=self._api_key) if self._api_key else openai.OpenAI()
            )
        return self._client

    def complete(self, request: ModelRequest, model: str) -> ModelResponse:
        client = self._ensure_client()
        messages = []
        if request.cacheable_prefix or request.system:
            messages.append(
                {
                    "role": "system",
                    "content": f"{request.cacheable_prefix}\n\n{request.system}".strip(),
                }
            )
        messages.extend(request.messages())

        raw = client.chat.completions.create(
            model=model, max_tokens=request.max_tokens, messages=messages
        )
        choice = raw.choices[0]
        usage = Usage(
            tokens_in=getattr(raw.usage, "prompt_tokens", 0) or 0,
            tokens_out=getattr(raw.usage, "completion_tokens", 0) or 0,
        )
        return ModelResponse(
            text=choice.message.content or "",
            usage=usage,
            stop_reason=getattr(choice, "finish_reason", None),
            model=getattr(raw, "model", model),
        )


PROVIDERS: dict[str, type[ModelProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
}


def build_provider(name: str) -> ModelProvider:
    try:
        return PROVIDERS[name]()
    except KeyError as exc:
        raise ValueError(f"unknown model provider {name!r}") from exc


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
        self._enforce_ceiling(request)

        def once() -> ModelResponse:
            try:
                response = self.provider.complete(request, self.cfg.model)
            except Exception as exc:
                raise ModelError(
                    f"{self.cfg.role}: provider call raised {type(exc).__name__}: {exc}",
                    ResponseClass.TRANSIENT,
                ) from exc
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
            on_retry=lambda attempt, delay, exc: log.warning(
                "%s retry %d after %.1fs: %s", self.cfg.role, attempt, delay, exc
            ),
        )

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
        return not is_priced(self.cfg.model)
