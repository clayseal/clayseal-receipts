"""Actionable error types.

Per the spec, every error carries a machine code, a human-readable message,
and a plain-English suggestion so a developer can fix a problem in under a
minute without reading docs. Routers translate these into HTTP responses with
a consistent JSON shape.
"""
from __future__ import annotations


class AgentAuthError(Exception):
    """Base class for all domain errors."""

    code: str = "agentauth_error"
    http_status: int = 400

    def __init__(self, message: str, *, suggestion: str = "", **details: object) -> None:
        super().__init__(message)
        self.message = message
        self.suggestion = suggestion
        self.details = details

    def to_dict(self) -> dict:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "suggestion": self.suggestion,
                **({"details": self.details} if self.details else {}),
            }
        }


class InvalidAPIKeyError(AgentAuthError):
    code = "invalid_api_key"
    http_status = 401


class TTLOutOfRangeError(AgentAuthError):
    code = "ttl_out_of_range"
    http_status = 400


class AttestationDeniedError(AgentAuthError):
    """Attestation failed: a forged/unsigned document, a signature that matches
    no registered node attestor, or selectors that match no registration entry.
    The workload could not prove it is entitled to the identity it requested."""

    code = "attestation_denied"
    http_status = 403


class NodeAttestorError(AgentAuthError):
    """A malformed node attestor registration (bad type or key material)."""

    code = "invalid_node_attestor"
    http_status = 400


class RegistrationEntryError(AgentAuthError):
    """A malformed registration entry (e.g. empty selectors)."""

    code = "invalid_registration_entry"
    http_status = 400


class InvalidTokenError(AgentAuthError):
    code = "invalid_token"
    http_status = 401


class TokenExpiredError(AgentAuthError):
    code = "token_expired"
    http_status = 401


class AgentRevokedError(AgentAuthError):
    code = "agent_revoked"
    http_status = 401


class AgentNotFoundError(AgentAuthError):
    code = "agent_not_found"
    http_status = 404


class BiscuitError(AgentAuthError):
    """A capability token that is malformed or not signed by the customer's
    Biscuit root key -- it cannot even be parsed/verified."""

    code = "invalid_biscuit"
    http_status = 400


class ProofOfPossessionError(AgentAuthError):
    """A capability operation was attempted without a valid proof that the caller
    holds the workload's SPIFFE private key (missing or forged signature)."""

    code = "pop_required"
    http_status = 403


class CapabilityDeniedError(AgentAuthError):
    """The capability token does not grant the requested ``(resource, action)``
    (never granted, attenuated away, or expired)."""

    code = "capability_denied"
    http_status = 403
