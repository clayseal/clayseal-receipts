from __future__ import annotations

from typing import Any

from harness.types import CaseResult


def bundle_identity_flags(bundle: dict[str, Any]) -> dict[str, Any]:
    """Extract SPIFFE / identity-evidence flags from an exported bundle."""
    authority = bundle.get("authority") or {}
    identity = bundle.get("identity") or {}
    spiffe_id = authority.get("workload_principal") or authority.get("subject_id")
    flags = {
        "spiffe_in_authority": bool(spiffe_id and str(spiffe_id).startswith("spiffe://")),
        "identity_section_present": bool(identity.get("jwt_svid") and identity.get("issuer_jwks")),
        "spiffe_id": spiffe_id,
    }
    if flags["identity_section_present"]:
        from agentauth.receipts.identity_evidence import identity_issues

        issues = identity_issues(bundle)
        flags["identity_verify_ok"] = len(issues) == 0
        flags["identity_issue_count"] = len(issues)
    else:
        flags["identity_verify_ok"] = None
        flags["identity_issue_count"] = None
    return flags


def summarize_identity(results: list[CaseResult]) -> dict[str, Any]:
    relevant = [item for item in results if item.metadata.get("with_identity")]
    if not relevant:
        return {}

    def _rate(key: str) -> float | None:
        values = [item.metadata.get(key) for item in relevant]
        present = [value for value in values if value is not None]
        if not present:
            return None
        return sum(1 for value in present if value) / len(present)

    return {
        "counts": {
            "cases": len(relevant),
            "exported": sum(1 for item in relevant if item.export_ok),
        },
        "rates": {
            "spiffe_in_authority_rate": _rate("spiffe_in_authority"),
            "identity_section_rate": _rate("identity_section_present"),
            "identity_verify_ok_rate": _rate("identity_verify_ok"),
            "live_validate_ok_rate": _rate("live_validate_ok"),
        },
        "cases": [
            {
                "case_id": item.case_id,
                "suite": item.suite,
                "spiffe_id": item.metadata.get("spiffe_id"),
                "identity_verify_ok": item.metadata.get("identity_verify_ok"),
                "live_validate_ok": item.metadata.get("live_validate_ok"),
            }
            for item in sorted(relevant, key=lambda row: (row.suite, row.case_id))
        ],
    }
