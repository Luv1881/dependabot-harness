"""The bounded agent loop.

Runs request → tool calls → results → request until the model answers in prose or the
tool budget is spent. The budget is the toolbox's, so the cap is enforced by the thing
that executes the tools rather than by the thing that counts turns.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..models import ModelClient, ModelRequest, ModelResponse
from .toolbox import Toolbox, ToolCallCapReached

log = logging.getLogger(__name__)


@dataclass
class LoopResult:
    response: ModelResponse
    tool_calls_used: int
    cap_reached: bool = False


def run_agent_loop(
    client: ModelClient,
    request: ModelRequest,
    toolbox: Toolbox,
    *,
    repo: str,
    stage: str,
    alert_key: str | None = None,
) -> LoopResult:
    """Drive one agent to a final answer.

    Every tool call the model requests is executed and its result fed back. When the
    toolbox refuses because the cap is spent, the loop stops and reports it: the caller
    turns that into `could_not_determine` rather than letting the model answer anyway.
    """
    while True:
        response = client.complete(request, repo=repo, stage=stage, alert_key=alert_key)
        if not response.tool_calls:
            return LoopResult(response=response, tool_calls_used=toolbox.used)

        results: list[dict[str, Any]] = []
        for call in response.tool_calls:
            try:
                output = toolbox.dispatch(str(call.get("name", "")), dict(call.get("input") or {}))
            except ToolCallCapReached:
                log.info("tool budget spent after %d calls", toolbox.used)
                return LoopResult(response=response, tool_calls_used=toolbox.used, cap_reached=True)
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": call.get("id", ""),
                    "content": output,
                }
            )

        request.history.append({"role": "assistant", "content": response.raw_content})
        request.history.append({"role": "user", "content": results})
