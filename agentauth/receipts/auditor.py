"""Compliance-facing evidence summaries (L4-8)."""

from __future__ import annotations

from typing import Any

from agentauth.receipts.explain import explain_receipt_bundle
from agentauth.core.signing import (
    trusted_signer_policy_from_env,
    verify_bundle_signatures,
)


def auditor_evidence_summary(
    bundle: dict[str, Any],
    *,
    profile: str | None = None,
    siem_format: str | None = None,
) -> dict[str, Any] | str:
    """
    Compact summary for auditors and GRC tools.

    Omits raw model input/output; includes decision, assurance, policy binding,
    touched resources, and signature status when present.

    With ``profile``, returns a compliance-mapped export. With ``siem_format``,
    returns an ECS/OTel/CEF record instead of the default summary JSON.
    """
    if siem_format is not None:
        from agentauth.receipts.compliance import export_siem_record

        return export_siem_record(bundle, format=siem_format)

    if profile is not None:
        from agentauth.receipts.compliance import export_compliance_mapped

        return export_compliance_mapped(bundle, profile)
    explain = explain_receipt_bundle(bundle)
    policy = bundle.get("policy", {})
    authority = bundle.get("authority", {})
    execution_context = bundle.get("execution_context", {})
    signatures = bundle.get("signatures", [])

    summary: dict[str, Any] = {
        "proof_id": explain["proof_id"],
        "schema": bundle.get("schema"),
        "sdk_version": bundle.get("sdk_version"),
        "exported_at": bundle.get("exported_at"),
        "decision": {
            "outcome": explain["decision"]["outcome"],
            "policy_satisfied": explain["decision"]["policy_satisfied"],
            "violations": explain["decision"]["violations"],
            "approval_state": explain["decision"].get("approval_state"),
            "obligations": explain["decision"].get("obligations", []),
            "can_execute": explain["decision"].get("can_execute"),
            "blocking_obligations": explain["decision"].get("blocking_obligations", []),
        },
        "budget": explain.get("budget"),
        "assurance": explain["assurance"],
        "policy": {
            "name": policy.get("name"),
            "version": policy.get("version"),
            "commitment": explain["policy"]["commitment"],
        },
        "authority": {
            "authority_id": authority.get("authority_id"),
            "authority_version": authority.get("authority_version"),
            "session_id": authority.get("session_id"),
        },
        "action": explain.get("action"),
        "touched_resources": list(execution_context.get("touched_resources", [])),
        "lineage": explain.get("lineage"),
        "evidence_refs": explain.get("evidence_refs"),
        "verification": explain["verification"],
        "warnings": explain["warnings"],
        "signature_count": len(signatures),
    }

    if signatures:
        summary["signatures"] = verify_bundle_signatures(
            bundle,
            **trusted_signer_policy_from_env(),
        )

    return summary
