"""Baseline integrity models for the soundness benchmark's contrast ladder.

These are NOT the product — they are reference comparators run through the *same*
tamper battery as `verify_receipt_bundle`, so the report can show where the obvious
alternatives silently accept tampered receipts and AgentAuth does not.

  * plaintext_verify   — plain structured logging: no integrity at all.
  * naive_canonical_verify — signs/binds only the proof-committed core (output,
    execution_context, policy commitment, decision outcome) but leaves the
    human-facing top-level projections, identity, audit_record contents, and
    evidence unbound. This is the common "sign the proof, copy fields out for
    display" design — a faithful model, not a strawman (it really does catch the
    canonical class); the gap it leaves is exactly what AgentAuth closes.

Each returns the same shape as `verify_receipt_bundle` so the tamper engine can
judge them interchangeably.
"""

from __future__ import annotations

from typing import Any

from agentauth.core.hash_util import hash_canonical_json
from agentauth.receipts.proof import ExecutionProof
from agentauth.receipts.verification import (
    VerificationIssue,
    VerifyErrorCode,
    verification_result,
)


def _result(valid: bool, issues: list[VerificationIssue]) -> dict[str, Any]:
    return verification_result(
        valid=valid, issues=issues, cryptographic={}, decision={}, assurance={}
    )


def plaintext_verify(bundle: dict[str, Any]) -> dict[str, Any]:
    """Baseline 0 — plain structured logging (OpenTelemetry / JSON logs). Reads the
    record and declares it fine; any field can be edited undetected."""
    return _result(True, [])


def signed_payload_verify(bundle: dict[str, Any]) -> dict[str, Any]:
    """Baseline 1 — a JWS/cosign-style signature over the model *response* only (the
    common 'we sign the agent's output' design). Binds `output` to the proof commitment
    and nothing else, so any identity/policy/decision/context field is editable."""
    proof_dict = bundle.get("execution_proof")
    if not isinstance(proof_dict, dict):
        return _result(False, [VerificationIssue(VerifyErrorCode.PROOF_INVALID, "no proof")])
    try:
        proof = ExecutionProof.from_dict(proof_dict)
    except Exception:
        return _result(
            False, [VerificationIssue(VerifyErrorCode.PROOF_INVALID, "unparseable proof")]
        )
    output = bundle.get("output")
    if isinstance(output, dict) and hash_canonical_json(output) != proof.output_hash:
        return _result(False, [VerificationIssue(VerifyErrorCode.OUTPUT_MISMATCH, "output")])
    return _result(True, [])


def hash_chain_log_verify(bundle: dict[str, Any]) -> dict[str, Any]:
    """Baseline 2 — an append-only hash-chained audit log (immudb / auditd / Trillian
    style). Re-derives the audit record's `record_hash` from its content, so it catches
    tampering of the *logged event*, but binds nothing about the receipt body (output,
    identity, policy, decision, top-level authority, evidence) that isn't in the log
    record."""
    record = bundle.get("audit_record")
    if not isinstance(record, dict) or not record.get("record_hash"):
        return _result(True, [])  # nothing logged to check
    body = {
        "proof_id": record.get("proof_id"),
        "execution_proof_hash": record.get("execution_proof_hash"),
        "action": record.get("action"),
        "authorization_context": record.get("authorization_context") or {},
        "created_at": record.get("created_at"),
        "prev_hash": record.get("prev_hash"),
    }
    if hash_canonical_json(body) != record.get("record_hash"):
        return _result(
            False,
            [VerificationIssue(VerifyErrorCode.AUDIT_INCLUSION_INVALID, "record_hash mismatch")],
        )
    return _result(True, [])


def naive_canonical_verify(bundle: dict[str, Any]) -> dict[str, Any]:
    """Baseline 1 — bind only the proof-committed canonical core."""
    proof_dict = bundle.get("execution_proof")
    if not isinstance(proof_dict, dict):
        return _result(False, [VerificationIssue(VerifyErrorCode.PROOF_INVALID, "no proof")])
    try:
        proof = ExecutionProof.from_dict(proof_dict)
    except Exception:
        return _result(
            False, [VerificationIssue(VerifyErrorCode.PROOF_INVALID, "unparseable proof")]
        )

    issues: list[VerificationIssue] = []
    output = bundle.get("output")
    if isinstance(output, dict) and hash_canonical_json(output) != proof.output_hash:
        issues.append(VerificationIssue(VerifyErrorCode.OUTPUT_MISMATCH, "output mismatch"))
    ctx = bundle.get("execution_context")
    if isinstance(ctx, dict) and hash_canonical_json(ctx) != proof.context_hash:
        issues.append(
            VerificationIssue(VerifyErrorCode.CONTEXT_MISMATCH, "execution_context mismatch")
        )
    cert = bundle.get("certificate")
    if isinstance(cert, dict) and cert.get("policy_commitment") not in (
        None,
        proof.policy_commitment,
    ):
        issues.append(
            VerificationIssue(VerifyErrorCode.CERTIFICATE_MISMATCH, "policy_commitment mismatch")
        )
    decision = bundle.get("decision")
    if isinstance(decision, dict) and decision:
        if decision.get("outcome") != proof.decision_outcome.value:
            issues.append(
                VerificationIssue(VerifyErrorCode.DECISION_MISMATCH, "decision outcome mismatch")
            )
        if (
            "policy_satisfied" in decision
            and decision.get("policy_satisfied") != proof.policy_satisfied
        ):
            issues.append(
                VerificationIssue(VerifyErrorCode.DECISION_MISMATCH, "policy_satisfied mismatch")
            )
    return _result(not issues, issues)


# Ladder, weakest to strongest. AgentAuth's own verifier is added by the runner so it
# stays the single source of truth.
BASELINE_VERIFIERS = {
    "plaintext_log": plaintext_verify,
    "signed_payload": signed_payload_verify,
    "hash_chain_log": hash_chain_log_verify,
    "naive_canonical": naive_canonical_verify,
}
