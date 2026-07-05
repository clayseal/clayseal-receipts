"""Typed exception hierarchy for the AgentAuth SDK.

Mirrors the backend's actionable error envelope ``{code, message, suggestion}``
(see ``agentauth/backend/errors.py``). Every exception carries the machine ``code``,
a human ``message``, and a plain-English ``suggestion`` so a developer can fix a
denied action in under a minute without reading docs.
"""
from __future__ import annotations


class AgentAuthError(Exception):
    """Base class for every error raised by the SDK.

    ``str(exc)`` includes the suggestion when present, so the fix is visible in
    logs and tracebacks without extra plumbing.
    """

    code: str = "agentauth_error"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        suggestion: str = "",
        status_code: int | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        self.suggestion = suggestion
        self.status_code = status_code
        self.details = details or {}

    def __str__(self) -> str:
        if self.suggestion:
            return f"[{self.code}] {self.message} — {self.suggestion}"
        return f"[{self.code}] {self.message}"


# --- transport / auth ------------------------------------------------------ #
class TransportError(AgentAuthError):
    """The request never produced a structured AgentAuth response (network,
    DNS, timeout, or a non-JSON 5xx)."""

    code = "transport_error"


class InvalidAPIKeyError(AgentAuthError):
    code = "invalid_api_key"


# --- identity / tokens ----------------------------------------------------- #
class InvalidTokenError(AgentAuthError):
    code = "invalid_token"


class TokenExpiredError(AgentAuthError):
    code = "token_expired"


class AgentRevokedError(AgentAuthError):
    code = "agent_revoked"


class AgentNotFoundError(AgentAuthError):
    code = "agent_not_found"


class TTLOutOfRangeError(AgentAuthError):
    code = "ttl_out_of_range"


# --- capabilities ---------------------------------------------------------- #
class BiscuitError(AgentAuthError):
    """A capability token that is malformed or not signed by the customer's
    Biscuit root key."""

    code = "invalid_biscuit"


class ProofOfPossessionError(AgentAuthError):
    """A capability operation lacked a valid proof that the caller holds the
    workload's SPIFFE private key."""

    code = "pop_required"


class CapabilityDeniedError(AgentAuthError):
    """The capability token does not grant the requested ``(resource, action)``."""

    code = "capability_denied"


# Map backend error codes -> SDK exception classes for the HTTP layer.
ERROR_CODE_MAP: dict[str, type[AgentAuthError]] = {
    "invalid_api_key": InvalidAPIKeyError,
    "invalid_token": InvalidTokenError,
    "token_expired": TokenExpiredError,
    "agent_revoked": AgentRevokedError,
    "agent_not_found": AgentNotFoundError,
    "ttl_out_of_range": TTLOutOfRangeError,
    "invalid_biscuit": BiscuitError,
    "pop_required": ProofOfPossessionError,
    "capability_denied": CapabilityDeniedError,
}


def from_envelope(payload: dict, status_code: int) -> AgentAuthError:
    """Build the most specific SDK exception from a backend error envelope."""
    err = (payload or {}).get("error", {}) if isinstance(payload, dict) else {}
    code = err.get("code", "agentauth_error")
    message = err.get("message", "Request failed.")
    suggestion = err.get("suggestion", "")
    details = err.get("details", {})
    cls = ERROR_CODE_MAP.get(code, AgentAuthError)
    return cls(
        message,
        code=code,
        suggestion=suggestion,
        status_code=status_code,
        details=details,
    )
