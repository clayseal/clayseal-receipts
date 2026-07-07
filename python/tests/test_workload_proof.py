"""Workload proof signing and verification."""

from __future__ import annotations

from agentauth.core.signing import generate_keypair
from agentauth.receipts.workload_proof import (
    build_workload_proof_binding,
    credential_hash,
    sign_workload_proof,
    verify_workload_proof,
)


def test_workload_proof_roundtrip():
    key = generate_keypair()
    binding = build_workload_proof_binding(
        proof_id="proof-1",
        context_hash="sha256:ctx",
        output_hash="sha256:out",
        policy_commitment="sha256:policy",
        credential_hash_value=credential_hash("token"),
    )
    section = sign_workload_proof(binding, key)
    issues = verify_workload_proof(
        section,
        proof_id="proof-1",
        context_hash="sha256:ctx",
        output_hash="sha256:out",
        policy_commitment="sha256:policy",
        credential_hash_value=credential_hash("token"),
    )
    assert issues == []


def test_workload_proof_detects_tamper():
    key = generate_keypair()
    binding = build_workload_proof_binding(
        proof_id="proof-1",
        context_hash="sha256:ctx",
        output_hash="sha256:out",
        policy_commitment="sha256:policy",
        credential_hash_value=credential_hash("token"),
    )
    section = sign_workload_proof(binding, key)
    section["binding"]["output_hash"] = "sha256:evil"
    issues = verify_workload_proof(
        section,
        proof_id="proof-1",
        context_hash="sha256:ctx",
        output_hash="sha256:out",
        policy_commitment="sha256:policy",
        credential_hash_value=credential_hash("token"),
    )
    assert any("output_hash mismatch" in item for item in issues)
