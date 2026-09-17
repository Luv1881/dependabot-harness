"""Provider-agnostic model access, budget accounting, and response classification."""

from .budget import BudgetDecision, BudgetExceeded, BudgetLedger, Usage, price
from .client import (
    ContextCeilingExceeded,
    ModelClient,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    build_provider,
    required_api_key_env,
)
from .errors import Classification, ModelError, ProviderConfigurationError, ResponseClass, classify

__all__ = [
    "BudgetDecision",
    "BudgetExceeded",
    "BudgetLedger",
    "Classification",
    "ContextCeilingExceeded",
    "ModelClient",
    "ModelError",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "ProviderConfigurationError",
    "ResponseClass",
    "Usage",
    "build_provider",
    "classify",
    "price",
    "required_api_key_env",
]
