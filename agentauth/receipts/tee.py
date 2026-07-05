"""TEE quote ingestion and verification (SOTA-2)."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
from typing import Any

from agentauth.receipts.assurance import rats_roles_reference


class TeeQuoteFormat(str, Enum):
    NITRO_ENCLAVE_V1 = "nitro_enclave_v1"
    TDX_V1 = "tdx_v1"
    UNSUPPORTED = "unsupported"


@dataclass
class TeeQuote:
    """Hardware attestation quote attached to a TEE-hybrid proof bundle."""

    format: TeeQuoteFormat
    quote_b64: str
    report_data_hash: str | None = None
    max_age_seconds: int | None = 86400

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format.value,
            "quote_b64": self.quote_b64,
            "report_data_hash": self.report_data_hash,
            "max_age_seconds": self.max_age_seconds,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> TeeQuote:
        return cls(
            format=TeeQuoteFormat(raw.get("format", TeeQuoteFormat.UNSUPPORTED.value)),
            quote_b64=str(raw["quote_b64"]),
            report_data_hash=raw.get("report_data_hash"),
            max_age_seconds=raw.get("max_age_seconds", 86400),
        )

    def document_bytes(self) -> bytes:
        return base64.standard_b64decode(self.quote_b64.encode("ascii"))


def tee_verification_to_eat(result: dict[str, Any]) -> dict[str, Any]:
    """Return EAT-shaped claims from a TEE verification result."""
    if result.get("eat"):
        return dict(result["eat"])
    return {
        "eat_profile": "agent-receipts.eat-tee-v1",
        "ver": "1.0.0",
        "cnf": {"tee.kind": result.get("format", "unknown"), "verified": bool(result.get("valid"))},
    }


def rats_flow_for_tee_verification() -> dict[str, str]:
    """RATS roles for the TEE attestation verify path."""
    roles = rats_roles_reference()
    return {
        "attester": roles["agent_prover"],
        "verifier": roles["agent_receipts_verifier"],
        "relying_party": roles["evidence_consumer"],
    }


def tee_hybrid_attestation_blockers(quote: TeeQuote | dict[str, Any]) -> list[str]:
    """Hard failures for quote formats that must not satisfy ``tee_hybrid`` attestation."""
    if isinstance(quote, dict):
        fmt = str(quote.get("format", TeeQuoteFormat.UNSUPPORTED.value))
    else:
        fmt = quote.format.value
    if fmt == TeeQuoteFormat.TDX_V1.value:
        return [
            "tdx_v1 quote verification is not implemented; tee_hybrid attestation rejected"
        ]
    return []


def verify_tee_quote(quote: TeeQuote | dict[str, Any]) -> dict[str, Any]:
    """
    Verify a TEE attestation quote.

    ``nitro_enclave_v1`` performs real COSE + certificate chain validation against
    the AWS Nitro root CA. ``tdx_v1`` remains an explicit unsupported stub until
    a TDX verifier lands.
    """
    if isinstance(quote, dict):
        quote = TeeQuote.from_dict(quote)

    if quote.format == TeeQuoteFormat.UNSUPPORTED:
        return {
            "valid": False,
            "stub": True,
            "reasons": ["tee quote format unsupported"],
        }
    if not quote.quote_b64:
        return {
            "valid": False,
            "stub": True,
            "reasons": ["tee quote payload is empty"],
        }

    if quote.format == TeeQuoteFormat.NITRO_ENCLAVE_V1:
        from agentauth.receipts.tee_nitro import verify_nitro_attestation_document

        result = verify_nitro_attestation_document(
            quote.document_bytes(),
            report_data_hash=quote.report_data_hash,
            max_age_seconds=quote.max_age_seconds,
        )
        result["rats_roles"] = rats_flow_for_tee_verification()
        if result.get("valid"):
            result["tee_assurance"] = "tee_attested"
        else:
            result["tee_assurance"] = "tee_hybrid_claimed"
        return result

    if quote.format == TeeQuoteFormat.TDX_V1:
        return {
            "valid": False,
            "stub": True,
            "format": quote.format.value,
            "tee_assurance": "tee_hybrid_claimed",
            "reasons": ["tdx_v1 quote verification is not implemented yet"],
        }

    return {
        "valid": False,
        "stub": True,
        "reasons": [f"unknown tee quote format: {quote.format.value}"],
    }
