"""Structured verification issues and error codes (L4-5)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class VerifyErrorCode(str, Enum):
    SCHEMA_MISMATCH = "schema_mismatch"
    PROOF_INVALID = "proof_invalid"
    DECISION_MISMATCH = "decision_mismatch"
    AUTHORITY_MISMATCH = "authority_mismatch"
    SESSION_MISMATCH = "session_mismatch"
    CERTIFICATE_MISMATCH = "certificate_mismatch"
    STORED_VERIFICATION_MISMATCH = "stored_verification_mismatch"
    UNSUPPORTED_ASSURANCE = "unsupported_assurance"
    ASSURANCE_THRESHOLD_NOT_MET = "assurance_threshold_not_met"
    SIGNATURE_INVALID = "signature_invalid"
    POLICY_REEVAL_MISMATCH = "policy_reeval_mismatch"
    MANDATE_VIOLATION = "mandate_violation"
    CONTEXT_MISMATCH = "context_mismatch"
    OUTPUT_MISMATCH = "output_mismatch"
    AUDIT_INCLUSION_INVALID = "audit_inclusion_invalid"
    DELEGATION_INVALID = "delegation_invalid"
    STUB_PROOF_NOT_ALLOWED = "stub_proof_not_allowed"
    SESSION_PROOF_INVALID = "session_proof_invalid"
    SCITT_INVALID = "scitt_invalid"
    TILES_INVALID = "tiles_invalid"
    HPKE_RECIPIENT_MISMATCH = "hpke_recipient_mismatch"
    SIGNER_REVOKED = "signer_revoked"
    WITNESS_DIVERGENCE = "witness_divergence"


@dataclass
class VerificationIssue:
    code: VerifyErrorCode
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code.value, "message": self.message}


def issues_to_reasons(issues: list[VerificationIssue]) -> list[str]:
    return [issue.message for issue in issues]


def verification_result(
    *,
    valid: bool,
    issues: list[VerificationIssue],
    cryptographic: dict[str, Any],
    decision: dict[str, Any],
    assurance: dict[str, Any],
) -> dict[str, Any]:
    return {
        "valid": valid,
        "reasons": issues_to_reasons(issues),
        "issues": [item.to_dict() for item in issues],
        "cryptographic": cryptographic,
        "decision": decision,
        "assurance": assurance,
    }
