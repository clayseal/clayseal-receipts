from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentauth.core.runtime import AuthorityContext


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _capability_string(capability: dict[str, Any]) -> str | None:
    resource = str(capability.get("resource", "")).strip()
    action = str(capability.get("action", "")).strip()
    if not resource or not action:
        return None
    return f"{resource}:{action}"


def _infer_spiffe_issuer(spiffe_id: str | None) -> str | None:
    if not spiffe_id or not spiffe_id.startswith("spiffe://"):
        return None
    remainder = spiffe_id.removeprefix("spiffe://")
    return remainder.split("/", 1)[0] or None


def _infer_spiffe_customer_id(spiffe_id: str | None) -> str | None:
    if not spiffe_id or not spiffe_id.startswith("spiffe://"):
        return None
    parts = spiffe_id.removeprefix("spiffe://").split("/")
    try:
        customer_index = parts.index("customer")
    except ValueError:
        return None
    if customer_index + 1 >= len(parts):
        return None
    customer_id = parts[customer_index + 1].strip()
    return customer_id or None


@dataclass
class AuthorityBinding:
    """Normalized L1/L2 authority facts consumed by the L3/L4 runtime."""

    subject_id: str
    authority_id: str
    issuer: str
    tenant_id: str | None = None
    subject_type: str | None = None
    owner_ref: str | None = None
    workload_principal: str | None = None
    capabilities: list[str] = field(default_factory=list)
    scope_claims: list[str] = field(default_factory=list)
    capability_rules: list[dict[str, Any]] = field(default_factory=list)
    selectors: list[str] = field(default_factory=list)
    attestation_type: str | None = None
    delegation_chain: list[str] = field(default_factory=list)
    expires_at: str | None = None
    trust_tier: str | None = None
    proof_of_possession: bool | None = None
    presenter_key_hash: str | None = None
    has_capability_grant: bool | None = None
    evidence_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "authority_id": self.authority_id,
            "issuer": self.issuer,
            "tenant_id": self.tenant_id,
            "subject_type": self.subject_type,
            "owner_ref": self.owner_ref,
            "workload_principal": self.workload_principal,
            "capabilities": list(self.capabilities),
            "scope_claims": list(self.scope_claims),
            "capability_rules": list(self.capability_rules),
            "selectors": list(self.selectors),
            "attestation_type": self.attestation_type,
            "delegation_chain": list(self.delegation_chain),
            "expires_at": self.expires_at,
            "trust_tier": self.trust_tier,
            "proof_of_possession": self.proof_of_possession,
            "presenter_key_hash": self.presenter_key_hash,
            "has_capability_grant": self.has_capability_grant,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AuthorityBinding:
        return cls(
            subject_id=str(raw["subject_id"]),
            authority_id=str(raw["authority_id"]),
            issuer=str(raw["issuer"]),
            tenant_id=raw.get("tenant_id", raw.get("customer_id")),
            subject_type=raw.get("subject_type", raw.get("agent_type")),
            owner_ref=raw.get("owner_ref", raw.get("owner")),
            workload_principal=raw.get("workload_principal", raw.get("spiffe_id")),
            capabilities=[str(item) for item in raw.get("capabilities", [])],
            scope_claims=[
                str(item) for item in raw.get("scope_claims", raw.get("scope_strings", []))
            ],
            capability_rules=[
                dict(item)
                for item in raw.get(
                    "capability_rules",
                    raw.get("capability_descriptors", []),
                )
                if isinstance(item, dict)
            ],
            selectors=[str(item) for item in raw.get("selectors", [])],
            attestation_type=raw.get("attestation_type"),
            delegation_chain=[str(item) for item in raw.get("delegation_chain", [])],
            expires_at=raw.get("expires_at"),
            trust_tier=raw.get("trust_tier"),
            proof_of_possession=raw.get("proof_of_possession"),
            presenter_key_hash=raw.get(
                "presenter_key_hash",
                raw.get("bound_keyhash"),
            ),
            has_capability_grant=raw.get(
                "has_capability_grant",
                raw.get("has_capability_token"),
            ),
        )

    @classmethod
    def from_agentauth_credential(
        cls,
        raw: dict[str, Any],
        *,
        issuer: str | None = None,
        authority_id: str | None = None,
        attestation_type: str = "jwt_svid",
        trust_tier: str | None = None,
        delegation_chain: list[str] | None = None,
    ) -> AuthorityBinding:
        """
        Normalize a partner `AgentAuth` L1/L2 credential payload into the
        shared L3/L4 authority contract.

        Expected input shape mirrors `agentauth/backend/schemas.py::CredentialOut` and
        `sdk/python/agentauth/models.py::Credential`.
        """
        spiffe_id = raw.get("spiffe_id")
        agent_id = raw.get("agent_id")
        if not spiffe_id and not agent_id:
            raise KeyError("agentauth credential requires at least spiffe_id or agent_id")

        capability_descriptors = [
            dict(item) for item in raw.get("capabilities", []) if isinstance(item, dict)
        ]
        scope_claims = [str(item) for item in raw.get("scopes", [])]
        capability_strings = [
            text
            for text in (_capability_string(item) for item in capability_descriptors)
            if text is not None
        ]
        normalized_capabilities = _dedupe_strings(scope_claims + capability_strings)

        has_capability_grant = bool(raw.get("biscuit") or raw.get("has_biscuit"))
        presenter_key_hash = raw.get("bound_keyhash")
        proof_of_possession = bool(presenter_key_hash and has_capability_grant)

        inferred_spiffe_issuer = _infer_spiffe_issuer(spiffe_id)
        resolved_issuer = issuer or inferred_spiffe_issuer or "agentauth.io"
        resolved_tenant_id = raw.get("customer_id") or _infer_spiffe_customer_id(spiffe_id)

        if trust_tier is None:
            trust_tier = "sender_constrained" if proof_of_possession else "workload_attested"

        return cls(
            subject_id=str(spiffe_id or agent_id),
            authority_id=str(authority_id or agent_id or spiffe_id),
            issuer=resolved_issuer,
            tenant_id=resolved_tenant_id,
            subject_type=raw.get("agent_type"),
            owner_ref=raw.get("owner"),
            workload_principal=spiffe_id,
            capabilities=normalized_capabilities,
            scope_claims=scope_claims,
            capability_rules=capability_descriptors,
            selectors=[str(item) for item in raw.get("selectors", [])],
            attestation_type=attestation_type,
            delegation_chain=list(delegation_chain or []),
            expires_at=raw.get("expires_at"),
            trust_tier=trust_tier,
            proof_of_possession=proof_of_possession,
            presenter_key_hash=presenter_key_hash,
            has_capability_grant=has_capability_grant,
            evidence_verified=True,
        )

    def to_authority_context(
        self,
        *,
        authority_version: int = 1,
        session_id: str | None = None,
        prior_action_count: int = 0,
        resource_scope: list[str] | None = None,
        budget_refs: list[str] | None = None,
        approval_refs: list[str] | None = None,
    ) -> AuthorityContext:
        return AuthorityContext(
            authority_id=self.authority_id,
            subject_id=self.subject_id,
            issuer=self.issuer,
            tenant_id=self.tenant_id,
            subject_type=self.subject_type,
            owner_ref=self.owner_ref,
            workload_principal=self.workload_principal,
            authority_version=authority_version,
            session_id=session_id,
            prior_action_count=prior_action_count,
            capabilities=list(self.capabilities),
            scope_claims=list(self.scope_claims),
            capability_rules=list(self.capability_rules),
            selectors=list(self.selectors),
            attestation_type=self.attestation_type,
            delegation_chain=list(self.delegation_chain),
            expires_at=self.expires_at,
            trust_tier=self.trust_tier,
            proof_of_possession=self.proof_of_possession,
            presenter_key_hash=self.presenter_key_hash,
            has_capability_grant=self.has_capability_grant,
            evidence_verified=self.evidence_verified,
            resource_scope=list(resource_scope or []),
            budget_refs=list(budget_refs or []),
            approval_refs=list(approval_refs or []),
        )
