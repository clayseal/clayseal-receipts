"""AgentAuth namespace — receipts layer."""
from __future__ import annotations

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)

from agentauth.identity import (
    AgentAuth,
    AgentInfo,
    AgentSession,
    Credential,
    ValidationResult,
)
from agentauth.identity.errors import (
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
from agentauth.receipts import (
    AgentCertificate,
    AgentWrapper,
    AuditChain,
    AuthorityBinding,
    DecisionOutcome,
    DecisionResult,
    ExecutionProof,
    Policy,
    RunResult,
    build_receipt_bundle,
    verify_receipt_bundle,
)
from agentauth.receipts._version import __version__

__all__ = [
    "__version__",
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
    "AgentWrapper",
    "RunResult",
    "Policy",
    "AgentCertificate",
    "AuthorityBinding",
    "AuditChain",
    "ExecutionProof",
    "DecisionResult",
    "DecisionOutcome",
    "build_receipt_bundle",
    "verify_receipt_bundle",
]
