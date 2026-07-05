from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from agentauth.receipts.certificate import AgentCertificate, certificate_ref_hash
from agentauth.core.hash_util import hash_canonical_json


def _b64(data: bytes | None) -> str | None:
    return base64.standard_b64encode(data).decode("ascii") if data else None


def _b64_decode(value: str | None) -> bytes | None:
    return base64.standard_b64decode(value.encode("ascii")) if value else None


class AttestationPath(str, Enum):
    FULL_ZK = "full_zk"
    TEE_HYBRID = "tee_hybrid"
    SHADOW = "shadow"


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    PENDING_APPROVAL = "pending_approval"
    PENDING_STEP_UP = "pending_step_up"
    ALLOW_WITH_OBLIGATIONS = "allow_with_obligations"
    ALLOW_WITH_REVIEW = "allow_with_review"
    BUDGET_RESERVATION_REQUIRED = "budget_reservation_required"

    @classmethod
    def supported_values(cls) -> tuple[str, ...]:
        """Portable outcome vocabulary (L3-2)."""
        return tuple(item.value for item in cls)


@dataclass
class ProofBundle:
    inference_proof: bytes | None = None
    policy_proof: bytes | None = None
    composed_proof: bytes | None = None
    verification_key_id: str | None = None
    tee_quote: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "inference_proof_b64": _b64(self.inference_proof),
            "policy_proof_b64": _b64(self.policy_proof),
            "composed_proof_b64": _b64(self.composed_proof),
            "verification_key_id": self.verification_key_id,
            "tee_quote": self.tee_quote,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ProofBundle:
        return cls(
            inference_proof=_b64_decode(raw.get("inference_proof_b64")),
            policy_proof=_b64_decode(raw.get("policy_proof_b64")),
            composed_proof=_b64_decode(raw.get("composed_proof_b64")),
            verification_key_id=raw.get("verification_key_id"),
            tee_quote=raw.get("tee_quote"),
        )


@dataclass
class ExecutionProof:
    proof_id: UUID
    agent_id: UUID
    certificate_ref: str
    policy_commitment: str
    context_hash: str
    output_hash: str
    attestation_path: AttestationPath
    policy_satisfied: bool
    decision_outcome: DecisionOutcome
    authority_version: int
    session_id: str | None
    created_at: datetime
    obligations: list[str] = field(default_factory=list)
    bundle: ProofBundle = field(default_factory=ProofBundle)

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof_id": str(self.proof_id),
            "agent_id": str(self.agent_id),
            "certificate_ref": self.certificate_ref,
            "policy_commitment": self.policy_commitment,
            "context_hash": self.context_hash,
            "output_hash": self.output_hash,
            "attestation_path": self.attestation_path.value,
            "policy_satisfied": self.policy_satisfied,
            "decision_outcome": self.decision_outcome.value,
            "authority_version": self.authority_version,
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "obligations": list(self.obligations),
            "bundle": self.bundle.to_dict(),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ExecutionProof:
        return cls(
            proof_id=UUID(raw["proof_id"]),
            agent_id=UUID(raw["agent_id"]),
            certificate_ref=raw["certificate_ref"],
            policy_commitment=raw["policy_commitment"],
            context_hash=raw["context_hash"],
            output_hash=raw["output_hash"],
            attestation_path=AttestationPath(raw["attestation_path"]),
            policy_satisfied=bool(raw["policy_satisfied"]),
            decision_outcome=DecisionOutcome(raw.get("decision_outcome", "allow")),
            authority_version=int(raw.get("authority_version", 1)),
            session_id=raw.get("session_id"),
            created_at=datetime.fromisoformat(raw["created_at"]),
            obligations=list(raw.get("obligations", [])),
            bundle=ProofBundle.from_dict(raw.get("bundle", {})),
        )

    def verify(self) -> dict[str, Any]:
        reasons: list[str] = []
        tee_result: dict[str, Any] | None = None
        if self.attestation_path == AttestationPath.SHADOW:
            reasons.append("shadow mode: proofs are not cryptographically verified")
            return {"valid": False, "reasons": reasons}
        if not self.policy_satisfied:
            reasons.append("policy_satisfied is false")

        if self.attestation_path == AttestationPath.TEE_HYBRID and self.bundle.tee_quote:
            from agentauth.receipts.tee import tee_hybrid_attestation_blockers

            reasons.extend(tee_hybrid_attestation_blockers(self.bundle.tee_quote))

        if self.bundle.composed_proof:
            from agentauth.receipts.compose import (
                verify_composed,
                verify_composed_execution_bindings,
            )

            composed = verify_composed(self.bundle.composed_proof)
            if not composed.get("valid"):
                reasons.extend(composed.get("reasons", ["composed proof verification failed"]))
            reasons.extend(
                verify_composed_execution_bindings(
                    self.bundle.composed_proof,
                    expected_context_hash=self.context_hash,
                )
            )

        if self.attestation_path == AttestationPath.TEE_HYBRID:
            from agentauth.receipts.tee import verify_tee_quote

            if self.bundle.tee_quote:
                if not reasons:
                    tee_result = verify_tee_quote(self.bundle.tee_quote)
                    if not tee_result.get("valid"):
                        reasons.extend(
                            tee_result.get("reasons", ["tee quote verification failed"])
                        )
            else:
                reasons.append("tee_hybrid: no tee_quote attached")

        if not self.bundle.composed_proof:
            if self.bundle.policy_proof:
                from agentauth.receipts.prover import verify_structural_policy

                zk = verify_structural_policy(self.bundle.policy_proof)
                if not zk.get("valid"):
                    reasons.extend(zk.get("reasons", ["policy proof verification failed"]))
            elif self.attestation_path == AttestationPath.FULL_ZK:
                reasons.append("missing policy_proof bytes")

            if self.bundle.inference_proof:
                from agentauth.receipts.inference import verify_inference

                inf = verify_inference(self.bundle.inference_proof)
                if not inf.get("valid"):
                    reasons.extend(inf.get("reasons", ["inference proof verification failed"]))
            elif self.attestation_path == AttestationPath.FULL_ZK:
                reasons.append(
                    "full_zk: missing inference_proof or composed_proof bytes"
                )

        result: dict[str, Any] = {"valid": len(reasons) == 0, "reasons": reasons}
        if tee_result is not None:
            result["tee"] = tee_result
        return result

    @classmethod
    def from_action(
        cls,
        certificate: AgentCertificate,
        context: dict[str, Any],
        output: dict[str, Any],
        *,
        policy_satisfied: bool,
        path: AttestationPath,
        decision_outcome: DecisionOutcome,
        authority_version: int = 1,
        session_id: str | None = None,
        obligations: list[str] | None = None,
    ) -> ExecutionProof:
        return cls(
            proof_id=uuid4(),
            agent_id=certificate.agent_id,
            certificate_ref=certificate_ref_hash(certificate),
            policy_commitment=certificate.policy_commitment,
            context_hash=hash_canonical_json(context),
            output_hash=hash_canonical_json(output),
            attestation_path=path,
            policy_satisfied=policy_satisfied,
            decision_outcome=decision_outcome,
            authority_version=authority_version,
            session_id=session_id,
            created_at=datetime.now(timezone.utc),
            obligations=list(obligations or []),
        )
