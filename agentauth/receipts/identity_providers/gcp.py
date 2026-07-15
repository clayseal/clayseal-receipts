"""GCP service account / workload identity federation claim mapping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.identity_protocol import CapabilityAuthorizer, IdentitySession

from agentauth.receipts.identity_providers._claims import scopes_from_claims


def claims_from_gcp(raw: dict[str, Any]) -> dict[str, Any]:
    subject = raw.get("sub") or raw.get("email") or raw.get("google.subject")
    return {
        "sub": subject,
        "iss": raw.get("iss") or "https://accounts.google.com",
        "scopes": scopes_from_claims(raw, "scope", "scopes"),
        "tenant_id": raw.get("project_id") or raw.get("aud"),
        "owner_ref": raw.get("email") or raw.get("service_account_email"),
        "subject_type": raw.get("subject_type") or "gcp_service_account",
        "expires_at": raw.get("exp"),
    }


@dataclass
class GcpIdentityProvider:
    name: str = "gcp_service_account"

    def to_binding(
        self, raw: dict[str, Any], *, evidence_verified: bool = False
    ) -> AuthorityBinding:
        normalized = claims_from_gcp(raw)
        return AuthorityBinding.from_verified_credential(
            normalized,
            attestation_type="gcp_service_account",
            issuer=str(normalized.get("iss") or "gcp"),
            evidence_verified=evidence_verified,
        )

    def build_session(
        self,
        raw: dict[str, Any],
        *,
        capability_authorizer: CapabilityAuthorizer | None = None,
        evidence_verified: bool = False,
    ) -> IdentitySession:
        return IdentitySession(
            binding=self.to_binding(raw, evidence_verified=evidence_verified),
            provider=self.name,
            capability_authorizer=capability_authorizer,
            raw_credential=raw,
        )


provider = GcpIdentityProvider()
