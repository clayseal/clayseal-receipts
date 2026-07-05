"""AgentAuth - identity for agents (Python SDK).

Quickstart::

    from agentauth import AgentAuth

    auth = AgentAuth(api_key="aa_...", dev_attestation=True)  # localhost demos/tests
    agent = auth.identify(agent_type="researcher", owner="alice@acme.ai",
                          scopes=["db:read"])

    print(agent.token)                 # signed JWT to carry on outbound calls

    result = auth.validate(agent.token)
    assert result.valid
"""
from __future__ import annotations

from .client import AgentAuth
from .errors import (
    AgentAuthError,
    AgentNotFoundError,
    AgentRevokedError,
    BiscuitError,
    CapabilityDeniedError,
    InvalidAPIKeyError,
    InvalidTokenError,
    ProofOfPossessionError,
    TokenExpiredError,
    TransportError,
    TTLOutOfRangeError,
)
from .models import AgentInfo, Credential, ValidationResult
from .session import AgentSession

__version__ = "0.2.1"

__all__ = [
    "AgentAuth",
    "AgentSession",
    "Credential",
    "AgentInfo",
    "ValidationResult",
    "AgentAuthError",
    "TransportError",
    "InvalidAPIKeyError",
    "InvalidTokenError",
    "TokenExpiredError",
    "AgentRevokedError",
    "AgentNotFoundError",
    "TTLOutOfRangeError",
    "BiscuitError",
    "ProofOfPossessionError",
    "CapabilityDeniedError",
    "__version__",
]
