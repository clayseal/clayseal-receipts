"""Decision and evidence views split from ExecutionProof (L4-2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentauth.receipts.assurance import assurance_from_proof
from agentauth.core.decision import ApprovalMetadata, ApprovalState, DecisionResult, Obligation
from agentauth.receipts.proof import DecisionOutcome, ExecutionProof
from agentauth.core.runtime import ExecutionContext
from agentauth.receipts.wrapper import RunResult


@dataclass
class AuthorityContextRef:
    authority_id: str
    authority_version: int = 1
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_id": self.authority_id,
            "authority_version": self.authority_version,
            "session_id": self.session_id,
        }

    @classmethod
    def from_execution_context(cls, ctx: ExecutionContext) -> AuthorityContextRef:
        auth = ctx.authority
        return cls(
            authority_id=auth.authority_id,
            authority_version=auth.authority_version,
            session_id=auth.session_id,
        )


@dataclass
class DecisionRecord:
    """Export-facing decision semantics (not stored on ExecutionProof)."""

    outcome: DecisionOutcome
    policy_satisfied: bool
    violations: list[str] = field(default_factory=list)
    obligations: list[Obligation] = field(default_factory=list)
    recommended_action: str | None = None
    approval_state: ApprovalState = ApprovalState.NOT_REQUIRED
    approval_metadata: ApprovalMetadata | None = None
    authority: AuthorityContextRef | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "policy_satisfied": self.policy_satisfied,
            "violations": list(self.violations),
            "obligations": [item.to_dict() for item in self.obligations],
            "recommended_action": self.recommended_action,
            "approval_state": self.approval_state.value,
            "approval_metadata": (
                self.approval_metadata.to_dict() if self.approval_metadata else None
            ),
            "authority": self.authority.to_dict() if self.authority else None,
        }

    @classmethod
    def from_decision_result(
        cls,
        decision: DecisionResult,
        *,
        authority: AuthorityContextRef | None = None,
    ) -> DecisionRecord:
        return cls(
            outcome=decision.outcome,
            policy_satisfied=decision.policy_satisfied,
            violations=list(decision.violations),
            obligations=list(decision.obligations),
            recommended_action=decision.recommended_action,
            approval_state=decision.approval_state,
            approval_metadata=decision.approval_metadata,
            authority=authority,
        )


@dataclass
class EvidenceSummary:
    """Cryptographic evidence summary without duplicating proof bytes."""

    proof_id: str
    attestation_path: str
    assurance_level: str
    verification_key_id: str | None
    policy_satisfied: bool
    has_policy_proof: bool
    has_inference_proof: bool
    has_composed_proof: bool
    has_tee_quote: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "attestation_path": self.attestation_path,
            "assurance_level": self.assurance_level,
            "verification_key_id": self.verification_key_id,
            "policy_satisfied": self.policy_satisfied,
            "has_policy_proof": self.has_policy_proof,
            "has_inference_proof": self.has_inference_proof,
            "has_composed_proof": self.has_composed_proof,
            "has_tee_quote": self.has_tee_quote,
        }

    @classmethod
    def from_proof(cls, proof: ExecutionProof) -> EvidenceSummary:
        assurance = assurance_from_proof(proof)
        bundle = proof.bundle
        return cls(
            proof_id=str(proof.proof_id),
            attestation_path=proof.attestation_path.value,
            assurance_level=assurance.level.value,
            verification_key_id=bundle.verification_key_id,
            policy_satisfied=proof.policy_satisfied,
            has_policy_proof=bundle.policy_proof is not None,
            has_inference_proof=bundle.inference_proof is not None,
            has_composed_proof=bundle.composed_proof is not None,
            has_tee_quote=bundle.tee_quote is not None,
        )


def decision_record_from_run(result: RunResult) -> DecisionRecord:
    return DecisionRecord.from_decision_result(
        result.decision,
        authority=AuthorityContextRef.from_execution_context(result.execution_context),
    )


def evidence_summary_from_run(result: RunResult) -> EvidenceSummary:
    return EvidenceSummary.from_proof(result.proof)


def evidence_block_from_run(result: RunResult) -> dict[str, Any]:
    """Combined L4-2 export block."""
    block: dict[str, Any] = {
        "decision_record": decision_record_from_run(result).to_dict(),
        "summary": evidence_summary_from_run(result).to_dict(),
    }
    obligation_section = result.decision.obligation_section()
    if obligation_section:
        block["obligations"] = obligation_section
    authorization = (result.execution_context.authorization or {}) if result.execution_context else {}
    monitoring = authorization.get("monitoring")
    if isinstance(monitoring, dict):
        block["monitoring"] = monitoring
    return block
