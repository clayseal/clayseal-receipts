"""Trust-tier summaries for receipt evidence (L4-6, SOTA-3)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from agentauth.receipts.proof import AttestationPath, ExecutionProof


class TrustTier(str, Enum):
    """Ordered assurance taxonomy (low → high). See docs/assurance_taxonomy.md."""

    DECLARED = "declared"
    SIGNED = "signed"
    SENDER_CONSTRAINED = "sender_constrained"
    WORKLOAD_ATTESTED = "workload_attested"
    TEE_ATTESTED = "tee_attested"
    ZK_POLICY_PROVED = "zk_policy_proved"
    ZK_EXECUTION_PROVED = "zk_execution_proved"


TIER_ORDINAL: dict[TrustTier, int] = {
    TrustTier.DECLARED: 0,
    TrustTier.SIGNED: 1,
    TrustTier.SENDER_CONSTRAINED: 2,
    TrustTier.WORKLOAD_ATTESTED: 3,
    TrustTier.TEE_ATTESTED: 4,
    TrustTier.ZK_POLICY_PROVED: 5,
    TrustTier.ZK_EXECUTION_PROVED: 6,
}

TIER_SCALE_ID = "agent-receipts.trust-tier.v1"


class AssuranceLevel(str, Enum):
    """Implementation-specific assurance label stored on receipts."""

    SHADOW = "shadow"
    OPERATOR_SIGNED = "operator_signed"
    TEE_HYBRID_CLAIMED = "tee_hybrid_claimed"
    TEE_ATTESTED = "tee_attested"
    POLICY_PROVED = "policy_proved"
    COMPOSED_PROVED = "composed_proved"


class RatsRole(str, Enum):
    """RFC 9334 Remote Attestation Procedures roles."""

    ATTESTER = "attester"
    VERIFIER = "verifier"
    RELYING_PARTY = "relying_party"


# How Agent Receipts maps onto RATS for evidence consumers.
RATS_COMPONENT_ROLES: dict[str, RatsRole] = {
    "agent_prover": RatsRole.ATTESTER,
    "agent_receipts_verifier": RatsRole.VERIFIER,
    "evidence_consumer": RatsRole.RELYING_PARTY,
}


ASSURANCE_LEVEL_TO_TIER: dict[AssuranceLevel, TrustTier] = {
    AssuranceLevel.SHADOW: TrustTier.DECLARED,
    AssuranceLevel.OPERATOR_SIGNED: TrustTier.SIGNED,
    # Unverified TEE claims stay at the signed tier until quote verification (SOTA-2).
    AssuranceLevel.TEE_HYBRID_CLAIMED: TrustTier.SIGNED,
    AssuranceLevel.TEE_ATTESTED: TrustTier.TEE_ATTESTED,
    AssuranceLevel.POLICY_PROVED: TrustTier.ZK_POLICY_PROVED,
    AssuranceLevel.COMPOSED_PROVED: TrustTier.ZK_EXECUTION_PROVED,
}


def tier_ordinal(tier: TrustTier | str) -> int:
    resolved = TrustTier(tier) if isinstance(tier, str) else tier
    return TIER_ORDINAL[resolved]


def trust_tier_for_level(level: AssuranceLevel | str) -> TrustTier:
    resolved = AssuranceLevel(level) if isinstance(level, str) else level
    return ASSURANCE_LEVEL_TO_TIER[resolved]


def parse_trust_tier(value: TrustTier | AssuranceLevel | str) -> TrustTier:
    if isinstance(value, TrustTier):
        return value
    if isinstance(value, AssuranceLevel):
        return trust_tier_for_level(value)
    text = str(value)
    try:
        return TrustTier(text)
    except ValueError:
        return trust_tier_for_level(AssuranceLevel(text))


def meets_assurance_threshold(
    actual: TrustTier | AssuranceLevel | str,
    minimum: TrustTier | AssuranceLevel | str,
) -> bool:
    actual_tier = parse_trust_tier(actual)
    minimum_tier = parse_trust_tier(minimum)
    return tier_ordinal(actual_tier) >= tier_ordinal(minimum_tier)


def rats_roles_reference() -> dict[str, str]:
    return {name: role.value for name, role in RATS_COMPONENT_ROLES.items()}


@dataclass
class AssuranceSummary:
    level: AssuranceLevel
    attestation_path: str
    verification_key_id: str | None
    policy_satisfied: bool
    has_policy_proof: bool
    has_inference_proof: bool
    has_composed_proof: bool
    tee_verified: bool = False
    tee_assurance: str | None = None
    eat: dict[str, Any] | None = None

    @property
    def tier(self) -> TrustTier:
        return trust_tier_for_level(self.level)

    @property
    def tier_ordinal(self) -> int:
        return tier_ordinal(self.tier)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "level": self.level.value,
            "tier": self.tier.value,
            "tier_ordinal": self.tier_ordinal,
            "tier_scale": TIER_SCALE_ID,
            "attestation_path": self.attestation_path,
            "verification_key_id": self.verification_key_id,
            "policy_satisfied": self.policy_satisfied,
            "has_policy_proof": self.has_policy_proof,
            "has_inference_proof": self.has_inference_proof,
            "has_composed_proof": self.has_composed_proof,
            "tee_verified": self.tee_verified,
        }
        if self.tee_assurance is not None:
            payload["tee_assurance"] = self.tee_assurance
        if self.eat is not None:
            payload["eat"] = self.eat
        return payload


def enrich_assurance_dict(raw: dict[str, Any]) -> dict[str, Any]:
    """Add taxonomy fields to a stored or partial assurance block."""
    enriched = dict(raw)
    level = enriched.get("level")
    if level is not None:
        tier = trust_tier_for_level(AssuranceLevel(str(level)))
        enriched.setdefault("tier", tier.value)
        enriched.setdefault("tier_ordinal", tier_ordinal(tier))
    enriched.setdefault("tier_scale", TIER_SCALE_ID)
    return enriched


def assurance_from_proof(proof: ExecutionProof) -> AssuranceSummary:
    bundle = proof.bundle
    has_policy = bundle.policy_proof is not None
    has_inference = bundle.inference_proof is not None
    has_composed = bundle.composed_proof is not None
    tee_verified = False
    tee_assurance: str | None = None
    eat: dict[str, Any] | None = None

    if has_composed:
        level = AssuranceLevel.COMPOSED_PROVED
    elif has_policy and proof.attestation_path == AttestationPath.FULL_ZK:
        level = AssuranceLevel.POLICY_PROVED
    elif proof.attestation_path == AttestationPath.SHADOW:
        level = AssuranceLevel.SHADOW
    else:
        level = AssuranceLevel.OPERATOR_SIGNED

    if proof.attestation_path == AttestationPath.TEE_HYBRID:
        tee_quote = bundle.tee_quote
        if isinstance(tee_quote, dict):
            from agentauth.receipts.tee import tee_hybrid_attestation_blockers, verify_tee_quote

            blockers = tee_hybrid_attestation_blockers(tee_quote)
            if blockers:
                if not has_composed:
                    level = AssuranceLevel.TEE_HYBRID_CLAIMED
                tee_assurance = "tee_hybrid_claimed"
            else:
                tee_result = verify_tee_quote(tee_quote)
                tee_assurance = tee_result.get("tee_assurance")
                eat = tee_result.get("eat")
                if tee_result.get("valid"):
                    tee_verified = True
                    if not has_composed:
                        level = AssuranceLevel.TEE_ATTESTED
                elif not has_composed:
                    level = AssuranceLevel.TEE_HYBRID_CLAIMED
        elif not has_composed:
            level = AssuranceLevel.TEE_HYBRID_CLAIMED

    return AssuranceSummary(
        level=level,
        attestation_path=proof.attestation_path.value,
        verification_key_id=bundle.verification_key_id,
        policy_satisfied=proof.policy_satisfied,
        has_policy_proof=has_policy,
        has_inference_proof=has_inference,
        has_composed_proof=has_composed,
        tee_verified=tee_verified,
        tee_assurance=tee_assurance,
        eat=eat,
    )


def assurance_from_bundle(bundle: dict[str, Any]) -> AssuranceSummary:
    if "execution_proof" in bundle:
        proof = ExecutionProof.from_dict(bundle["execution_proof"])
        return assurance_from_proof(proof)

    raw = bundle.get("assurance")
    if raw is None:
        evidence = bundle.get("evidence", {})
        if isinstance(evidence, dict):
            raw = evidence.get("assurance")
    if isinstance(raw, dict) and "level" in raw:
        return AssuranceSummary(
            level=AssuranceLevel(raw["level"]),
            attestation_path=str(raw.get("attestation_path", "shadow")),
            verification_key_id=raw.get("verification_key_id"),
            policy_satisfied=bool(raw.get("policy_satisfied", False)),
            has_policy_proof=bool(raw.get("has_policy_proof", False)),
            has_inference_proof=bool(raw.get("has_inference_proof", False)),
            has_composed_proof=bool(raw.get("has_composed_proof", False)),
        )
    raise KeyError("bundle missing execution_proof and assurance.level")
