"""Authority binding state labels for exports and verifier UX."""

from __future__ import annotations

from typing import Any

BINDING_UNBOUND = "unbound"
BINDING_DECLARED = "declared"
BINDING_SIGNED = "signed"
BINDING_AGENTAUTH_VERIFIED = "agentauth_verified"
BINDING_WORKLOAD_ATTESTED = "workload_attested"


def authority_block_from_bundle(bundle: dict[str, Any]) -> dict[str, Any] | None:
    execution_context = bundle.get("execution_context")
    if isinstance(execution_context, dict) and isinstance(execution_context.get("authority"), dict):
        return execution_context["authority"]
    authority = bundle.get("authority")
    return authority if isinstance(authority, dict) else None


def derive_binding_state(
    bundle: dict[str, Any],
    *,
    identity_bound: bool,
    workload_proof_valid: bool = False,
) -> str:
    """Classify how strongly the receipt authority is bound to an attested identity."""
    if workload_proof_valid and identity_bound:
        return BINDING_WORKLOAD_ATTESTED
    authority = authority_block_from_bundle(bundle) or {}
    if not identity_bound:
        subject = authority.get("subject_id") or authority.get("workload_principal")
        if subject and subject != authority.get("authority_id"):
            return BINDING_DECLARED
        return BINDING_UNBOUND
    if bundle.get("workload_proof"):
        return BINDING_WORKLOAD_ATTESTED if workload_proof_valid else BINDING_AGENTAUTH_VERIFIED
    if authority.get("evidence_verified") or authority.get("proof_of_possession"):
        return BINDING_AGENTAUTH_VERIFIED
    if bundle.get("signatures"):
        return BINDING_SIGNED
    return BINDING_DECLARED


def annotate_authority_binding_state(
    authority: dict[str, Any],
    *,
    binding_state: str,
) -> dict[str, Any]:
    annotated = dict(authority)
    annotated["binding_state"] = binding_state
    return annotated
