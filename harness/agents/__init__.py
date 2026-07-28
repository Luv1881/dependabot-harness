"""Bounded agent surfaces: the tools an agent may call, and their limits."""

from .loop import LoopResult, run_agent_loop
from .toolbox import TOOL_DEFINITIONS, Toolbox, ToolCall, ToolCallCapReached

__all__ = [
    "TOOL_DEFINITIONS",
    "LoopResult",
    "ToolCall",
    "ToolCallCapReached",
    "Toolbox",
    "run_agent_loop",
]
