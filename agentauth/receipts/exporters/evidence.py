"""A receipt bundle condensed into a compliance-evidence record.

The differentiated story for compliance platforms is not the raw bundle — it is
the *verification result*: cryptographic pass/fail with reasons, which is
system-generated completeness-and-accuracy evidence (AT-C 205 IPE) rather than
a screenshot. This record is what the Vanta/Drata exporters push.
"""

from __future__ import annotations

from typing import Any


def receipt_evidence_record(bundle: dict[str, Any], *, verify: bool = True) -> dict[str, Any]:
    """Flatten a receipt bundle into a compliance-evidence record.

    With ``verify=True`` (default) the bundle is run through
    :func:`agentauth.receipts.export.verify_receipt_bundle` and the verdict is
    embedded; a verification crash is recorded as a failed verification, never
    raised (exporters must not break the run that produced the receipt).
    """
    action = bundle.get("action") or {}
    decision = bundle.get("decision") or {}
    certificate = bundle.get("certificate") or {}
    policy = bundle.get("policy") or {}
    record: dict[str, Any] = {
        "proof_id": (bundle.get("execution_proof") or {}).get("proof_id"),
        "receipt_schema": bundle.get("schema"),
        "agent_id": certificate.get("agent_id"),
        "agent_name": certificate.get("display_name"),
        "action": action.get("action_name"),
        "resource_ref": action.get("resource_ref"),
        "side_effect_level": action.get("side_effect_level"),
        "outcome": decision.get("outcome"),
        "policy_name": policy.get("name"),
        "policy_version": policy.get("version"),
        "policy_commitment": policy.get("commitment"),
        "exported_at": bundle.get("exported_at"),
        "sdk_version": bundle.get("sdk_version"),
    }
    if verify:
        try:
            from agentauth.receipts.export import verify_receipt_bundle

            result = verify_receipt_bundle(bundle)
            record["verification"] = {
                "valid": bool(result.get("valid")),
                "reasons": list(result.get("reasons", [])),
            }
        except Exception as exc:  # noqa: BLE001 - any crash is a failed verification
            record["verification"] = {
                "valid": False,
                "reasons": [f"verification error: {exc}"],
            }
    return record
