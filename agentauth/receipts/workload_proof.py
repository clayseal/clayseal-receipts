"""Portable receipt-bound workload proof-of-possession (Clay Seal P0)."""

from __future__ import annotations

from typing import Any

from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.signing import SigningKey, signature_key_id_matches, verify

WORKLOAD_PROOF_SCHEMA = "clay-seal.workload-proof.v1"


def credential_hash(token: str) -> str:
    """Stable hash of the Clay Seal credential bearer token."""
    return hash_canonical_json({"credential": token})


def build_workload_proof_binding(
    *,
    proof_id: str,
    context_hash: str,
    output_hash: str,
    policy_commitment: str,
    credential_hash_value: str,
) -> dict[str, Any]:
    """Binding document signed by the workload key and verified offline."""
    return {
        "schema": WORKLOAD_PROOF_SCHEMA,
        "proof_id": proof_id,
        "context_hash": context_hash,
        "output_hash": output_hash,
        "policy_commitment": policy_commitment,
        "credential_hash": credential_hash_value,
    }


def sign_workload_proof(binding: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    if binding.get("schema") != WORKLOAD_PROOF_SCHEMA:
        raise ValueError(f"unsupported workload proof schema: {binding.get('schema')!r}")
    return {"binding": binding, "signature": key.sign(binding)}


def load_signing_key_from_pem(pem: str) -> SigningKey:
    from agentauth.core.signing import load_signing_key_from_pem as _load

    return _load(pem)


def verify_workload_proof(
    section: dict[str, Any] | None,
    *,
    proof_id: str,
    context_hash: str,
    output_hash: str,
    policy_commitment: str,
    credential_hash_value: str | None = None,
    presenter_key_hash: str | None = None,
) -> list[str]:
    """Validate optional workload_proof section against receipt fields."""
    if not section:
        return []

    binding = section.get("binding")
    signature = section.get("signature")
    if not isinstance(binding, dict) or not isinstance(signature, dict):
        return ["workload_proof requires binding and signature"]

    issues: list[str] = []
    if binding.get("schema") != WORKLOAD_PROOF_SCHEMA:
        issues.append(f"unsupported workload_proof schema: {binding.get('schema')!r}")
    expected = build_workload_proof_binding(
        proof_id=proof_id,
        context_hash=context_hash,
        output_hash=output_hash,
        policy_commitment=policy_commitment,
        credential_hash_value=str(binding.get("credential_hash", "")),
    )
    for field in ("proof_id", "context_hash", "output_hash", "policy_commitment"):
        if binding.get(field) != expected[field]:
            issues.append(f"workload_proof binding {field} mismatch")
    if credential_hash_value is not None and binding.get("credential_hash") != credential_hash_value:
        issues.append("workload_proof credential_hash mismatch")

    if not signature_key_id_matches(signature):
        issues.append("workload_proof signature key_id does not match public_key")
    elif not verify(binding, signature):
        issues.append("workload_proof signature invalid")
    elif presenter_key_hash is not None:
        public_key = signature.get("public_key")
        if public_key:
            from agentauth.core.signing import key_id_for_public_key_hex

            derived = key_id_for_public_key_hex(public_key)
            if derived != presenter_key_hash and public_key != presenter_key_hash:
                issues.append("workload_proof signer does not match authority presenter_key_hash")

    return issues
