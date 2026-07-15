"""Portable receipt bundles for design partners and offline verification."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentauth.receipts._version import __version__
from agentauth.receipts.assurance import (
    assurance_from_proof,
    enrich_assurance_dict,
    meets_assurance_threshold,
    parse_trust_tier,
    tier_ordinal,
)
from agentauth.receipts.audit import (
    AuditChain,
    audit_record_to_dict,
    checkpoint_trust_issues,
    trusted_audit_log_policy_from_env,
)
from agentauth.core.budget import CapabilityBudget
from agentauth.receipts.certificate import AgentCertificate, certificate_ref_hash
from agentauth.receipts.evidence_refs import EvidenceRefs
from agentauth.receipts.handoff import SessionHandoffArtifact
from agentauth.core.hash_util import hash_canonical_json
from agentauth.receipts.identity_evidence import identity_issues
from agentauth.core.lineage import AuthorityLineage
from agentauth.receipts.policy import Policy
from agentauth.receipts.proof import ExecutionProof
from agentauth.receipts.receipt_schema import (
    RECEIPT_BUNDLE_SCHEMA_V2,
    SchemaVersion,
    build_v2_sections,
    is_supported_schema,
    policy_violations_from_bundle,
    required_sections_present,
    schema_id,
    stored_assurance_dict,
)
from agentauth.core.signing import (
    SigningKey,
    trusted_signer_policy_from_env,
    verify,
    verify_bundle_signatures,
)
from agentauth.receipts.verification import (
    VerificationIssue,
    VerifyErrorCode,
    verification_result,
)
from agentauth.receipts.binding_state import BINDING_UNBOUND, derive_binding_state
from agentauth.receipts.wrapper import RunResult

REQUIRE_BUNDLE_SIGNATURES_ENV = "AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES"


def require_bundle_signatures_from_env() -> bool:
    return os.environ.get(REQUIRE_BUNDLE_SIGNATURES_ENV, "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def build_receipt_bundle(
    result: RunResult,
    *,
    certificate: AgentCertificate,
    policy: Policy | None = None,
    policy_path: str | Path | None = None,
    context: dict[str, Any] | None = None,
    lineage: AuthorityLineage | None = None,
    identity: dict[str, Any] | None = None,
    budgets: list[CapabilityBudget] | None = None,
    evidence_refs: EvidenceRefs | None = None,
    handoff: SessionHandoffArtifact | None = None,
    audit_chain: AuditChain | None = None,
    signed_mandate: dict[str, Any] | None = None,
    schema_version: SchemaVersion = "v2",
    scitt_issuer_key: SigningKey | None = None,
    scitt_issuer: str | None = None,
    scitt_subject: str | None = None,
    scitt_service_id: str | None = None,
    scitt_c2sp_origin: str | None = None,
    confidential_recipient_public_key: bytes | None = None,
) -> dict[str, Any]:
    """Canonical JSON-serializable receipt for a single agent/MCP action."""
    verification = result.proof.verify()
    authority = result.execution_context.authority.to_dict()
    action = result.execution_context.action.to_dict()
    execution_context = result.execution_context.to_dict()
    assurance = assurance_from_proof(result.proof).to_dict()
    budget_dicts = [item.to_dict() for item in budgets] if budgets else None

    common: dict[str, Any] = {
        "schema": schema_id(schema_version),
        "sdk_version": __version__,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "execution_proof": result.proof.to_dict(),
        "output": result.output,
        "verification": verification,
        "certificate": certificate.to_dict(),
    }

    if schema_version == "v2":
        common.update(
            build_v2_sections(
                result,
                assurance=assurance,
                authority=authority,
                action=action,
                execution_context=execution_context,
                budgets=budget_dicts,
            )
        )
    else:
        common.update(
            {
                "decision": result.decision.to_dict(),
                "authority": authority,
                "action": action,
                "execution_context": execution_context,
                "assurance": assurance,
                "evidence": _evidence_block_v1(result),
                "policy_violations": list(result.policy_violations),
                "recommended_action": result.recommended_action,
            }
        )

    if policy is not None:
        # `commitment_inputs` is the exact canonical dict the commitment hashes,
        # so a verifier can recompute the commitment and bind the human-facing
        # name/version/tier/capability projection to the proof (see EV-RT-2).
        common["policy"] = {
            "name": policy.name,
            "version": policy.version,
            "tier": policy.tier.value,
            "capability": policy.capability.value,
            "commitment": policy.commitment(),
            "commitment_inputs": policy.to_dict(),
        }
    if policy_path is not None:
        common["policy_path"] = str(policy_path)
    if context is not None:
        common["context"] = context
    if result.audit_record is not None:
        common["audit_record"] = audit_record_to_dict(result.audit_record)
        if audit_chain is not None:
            try:
                inclusion = audit_chain.inclusion_proof(result.audit_record.record_hash)
            except KeyError:
                inclusion = None
            if inclusion is not None:
                audit_inclusion: dict[str, Any] = {
                    "proof": inclusion,
                    "checkpoint": audit_chain.signed_checkpoint(),
                }
                if audit_chain.signing_key is not None:
                    audit_inclusion["log_public_key"] = audit_chain.signing_key.public_key_hex
                common["audit_inclusion"] = audit_inclusion
    if lineage is not None:
        common["lineage"] = lineage.to_dict()
    if identity is not None:
        # Embedded L1/L2 identity evidence: the signed JWT-SVID + issuer JWKS, so the
        # attested identity in `authority` can be authenticated offline (see
        # identity_evidence.identity_issues).
        common["identity"] = identity
    if budget_dicts and schema_version == "v1":
        common["budgets"] = budget_dicts
    if evidence_refs is not None:
        common["evidence_refs"] = evidence_refs.to_dict()
    if handoff is not None:
        common["handoff"] = handoff.to_dict()
    if signed_mandate is not None:
        from agentauth.core.mandate import mandate_bundle_section

        common["mandate"] = mandate_bundle_section(signed_mandate)

    if result.workload_proof is not None:
        common["workload_proof"] = result.workload_proof

    from agentauth.receipts.binding_state import (
        annotate_authority_binding_state,
        derive_binding_state,
    )

    binding_state = derive_binding_state(
        common,
        identity_bound=bool(identity),
        workload_proof_valid=result.workload_proof is not None,
    )
    if isinstance(common.get("authority"), dict):
        common["authority"] = annotate_authority_binding_state(
            common["authority"],
            binding_state=binding_state,
        )

    if scitt_issuer_key is not None:
        from agentauth.receipts.scitt_bundle import (
            DEFAULT_C2SP_ORIGIN,
            DEFAULT_SCITT_SERVICE_ID,
            build_scitt_section,
        )

        issuer = scitt_issuer or certificate.principal.principal_id
        subject = scitt_subject or str(result.proof.agent_id)
        common["scitt"] = build_scitt_section(
            common,
            issuer_key=scitt_issuer_key,
            issuer=issuer,
            subject=subject,
            audit_chain=audit_chain,
            service_id=scitt_service_id or DEFAULT_SCITT_SERVICE_ID,
            c2sp_origin=scitt_c2sp_origin or DEFAULT_C2SP_ORIGIN,
            confidential_recipient_public_key=confidential_recipient_public_key,
            mandate_section=common.get("mandate"),
        )
    return common


def _evidence_block_v1(result: RunResult) -> dict[str, Any]:
    from agentauth.receipts.evidence import evidence_block_from_run

    return evidence_block_from_run(result)


def export_bundle_for_audience(
    bundle: dict[str, Any],
    *,
    mode: str = "full",
    profile: str | None = None,
) -> dict[str, Any]:
    """Apply L4-8 export modes: full, compact, redacted, or compliance profile."""
    if profile is not None:
        from agentauth.receipts.compliance import export_compliance_mapped

        return export_compliance_mapped(bundle, profile)

    from agentauth.receipts.redact import redact_receipt_bundle

    if mode == "compact":
        return compact_receipt_bundle(bundle)
    if mode == "redacted":
        return redact_receipt_bundle(bundle)
    if mode == "full":
        return dict(bundle)
    raise ValueError(f"unknown export mode: {mode!r}")


def receipt_bundle_to_json(bundle: dict[str, Any], *, indent: int | None = 2) -> str:
    return json.dumps(bundle, indent=indent, sort_keys=True)


def write_receipt_bundle(path: str | Path, bundle: dict[str, Any]) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(receipt_bundle_to_json(bundle), encoding="utf-8")
    return dest


def load_receipt_bundle(path: str | Path) -> dict[str, Any]:
    dest = Path(path)
    if dest.suffix.lower() in {".cbor", ".cborhex"}:
        return load_receipt_bundle_cbor(dest)
    return json.loads(dest.read_text(encoding="utf-8"))


def load_receipt_bundle_cbor(path: str | Path) -> dict[str, Any]:
    from agentauth.receipts.scitt_bundle import bundle_from_cbor

    data = Path(path).read_bytes()
    return bundle_from_cbor(data)


def write_receipt_bundle_cbor(path: str | Path, bundle: dict[str, Any]) -> Path:
    from agentauth.receipts.scitt_bundle import bundle_to_cbor

    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(bundle_to_cbor(bundle))
    return dest


def write_receipts_ndjson(path: str | Path, bundles: Iterable[dict[str, Any]]) -> Path:
    """Write one receipt bundle per line (L4-8 NDJSON export)."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(bundle, sort_keys=True) for bundle in bundles]
    dest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return dest


def load_receipts_ndjson(path: str | Path) -> list[dict[str, Any]]:
    """Load receipt bundles from an NDJSON file."""
    rows: list[dict[str, Any]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped:
            rows.append(json.loads(stripped))
    return rows


def execution_proof_from_bundle(bundle: dict[str, Any]) -> ExecutionProof:
    return ExecutionProof.from_dict(bundle["execution_proof"])


def _mcp_arguments_hash_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    execution_context = bundle.get("execution_context")
    if not isinstance(execution_context, dict):
        return []
    authorization = execution_context.get("authorization")
    if not isinstance(authorization, dict) or authorization.get("protocol") != "mcp":
        return []
    stored_hash = authorization.get("arguments_hash")
    if not isinstance(stored_hash, str) or not stored_hash:
        return [
            VerificationIssue(
                VerifyErrorCode.CONTEXT_MISMATCH,
                "mcp authorization missing arguments_hash",
            )
        ]
    input_data = execution_context.get("input")
    if not isinstance(input_data, dict):
        return [
            VerificationIssue(
                VerifyErrorCode.CONTEXT_MISMATCH,
                "execution_context.input must be a dict for mcp tool receipts",
            )
        ]
    from agentauth.core.hash_util import hash_canonical_json

    expected = hash_canonical_json(input_data)
    if stored_hash != expected:
        return [
            VerificationIssue(
                VerifyErrorCode.CONTEXT_MISMATCH,
                "mcp arguments_hash does not match execution_context.input",
            )
        ]
    return []


def _monitoring_evidence_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    """Cross-check exported monitoring signal against committed policy thresholds (SM-23)."""
    issues: list[VerificationIssue] = []
    evidence = bundle.get("evidence") or {}
    monitoring = evidence.get("monitoring")
    if not isinstance(monitoring, dict):
        authorization = (bundle.get("execution_context") or {}).get("authorization") or {}
        monitoring = authorization.get("monitoring")
    if not isinstance(monitoring, dict):
        return issues

    policy_block = bundle.get("policy") or {}
    commitment_inputs = policy_block.get("commitment_inputs") or {}
    monitoring_policy = commitment_inputs.get("monitoring") or {}
    if not monitoring_policy.get("enabled"):
        return issues

    score = monitoring.get("score")
    if not isinstance(score, (int, float)):
        return issues

    review_threshold = monitoring_policy.get("review_threshold")
    block_threshold = monitoring_policy.get("block_threshold")
    outcome = (bundle.get("decision") or {}).get("outcome")

    if block_threshold is not None and score >= float(block_threshold) and outcome == "allow":
        issues.append(
            VerificationIssue(
                VerifyErrorCode.DECISION_MISMATCH,
                f"monitoring score {score} exceeds block threshold but outcome is allow",
            )
        )
    if (
        review_threshold is not None
        and score >= float(review_threshold)
        and outcome == "allow"
        and monitoring.get("review_required")
    ):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.DECISION_MISMATCH,
                "monitoring score requires review but outcome is allow",
            )
        )
    return issues


def _credential_access_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    """Verify credential access attestation matches policy (ID-2)."""
    issues: list[VerificationIssue] = []
    execution_context = bundle.get("execution_context")
    if not isinstance(execution_context, dict):
        return issues
    authorization = execution_context.get("authorization")
    if not isinstance(authorization, dict):
        return issues
    attestation = authorization.get("credential_access")
    if not isinstance(attestation, dict):
        return issues

    policy_block = bundle.get("policy") or {}
    commitment_inputs = policy_block.get("commitment_inputs") or {}
    cred_policy = commitment_inputs.get("credential_access") or {}
    if not cred_policy.get("enabled"):
        return issues

    if attestation.get("authorized") is False and (bundle.get("decision") or {}).get(
        "outcome"
    ) == "allow":
        blocked = attestation.get("blocked_paths") or []
        issues.append(
            VerificationIssue(
                VerifyErrorCode.DECISION_MISMATCH,
                f"credential access blocked for {blocked!r} but outcome is allow",
            )
        )
    return issues


def _artifact_publication_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    """Verify artifact publication attestation matches policy (CI-2)."""
    issues: list[VerificationIssue] = []
    execution_context = bundle.get("execution_context")
    if not isinstance(execution_context, dict):
        return issues
    authorization = execution_context.get("authorization")
    if not isinstance(authorization, dict):
        return issues
    publication = authorization.get("artifact_publication")
    if not isinstance(publication, dict):
        return issues

    policy_block = bundle.get("policy") or {}
    commitment_inputs = policy_block.get("commitment_inputs") or {}
    artifact_policy = commitment_inputs.get("artifact_guard") or {}
    if not artifact_policy.get("enabled"):
        return issues

    if publication.get("authorized") is False and (bundle.get("decision") or {}).get(
        "outcome"
    ) == "allow":
        issues.append(
            VerificationIssue(
                VerifyErrorCode.DECISION_MISMATCH,
                "artifact publication not authorized but outcome is allow",
            )
        )
    secret_scan = publication.get("secret_scan")
    if (
        isinstance(secret_scan, dict)
        and secret_scan.get("finding_count", 0) > 0
        and artifact_policy.get("deny_secret_in_artifacts")
        and (bundle.get("decision") or {}).get("outcome") == "allow"
    ):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.DECISION_MISMATCH,
                "artifact payload contains secrets but outcome is allow",
            )
        )
    return issues


def _anomaly_proof_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    """Verify committed anomaly score proof when present (SM-25)."""
    issues: list[VerificationIssue] = []
    evidence = bundle.get("evidence") or {}
    monitoring = evidence.get("monitoring")
    if not isinstance(monitoring, dict):
        authorization = (bundle.get("execution_context") or {}).get("authorization") or {}
        monitoring = authorization.get("monitoring")
    if not isinstance(monitoring, dict):
        return issues
    proof = monitoring.get("anomaly_proof")
    if not isinstance(proof, dict):
        return issues

    from agentauth.receipts.anomaly_proof import verify_anomaly_score_proof

    result = verify_anomaly_score_proof(proof)
    if not result.get("valid"):
        for reason in result.get("reasons", []):
            issues.append(
                VerificationIssue(VerifyErrorCode.DECISION_MISMATCH, str(reason))
            )
    return issues


def _mcp_tool_pin_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    execution_context = bundle.get("execution_context")
    if not isinstance(execution_context, dict):
        return []
    authorization = execution_context.get("authorization")
    if not isinstance(authorization, dict) or authorization.get("protocol") != "mcp":
        return []
    issues: list[VerificationIssue] = []
    for field, label in (
        ("tool_identity_hash", "tool identity"),
        ("tool_description_hash", "tool description"),
        ("tool_schema_hash", "tool schema"),
    ):
        value = authorization.get(field)
        if value is not None and not isinstance(value, str):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.CONTEXT_MISMATCH,
                    f"mcp {label} hash must be a string when present",
                )
            )
    return issues


def _output_context_binding_issues(
    bundle: dict[str, Any], proof: ExecutionProof
) -> list[VerificationIssue]:
    """Bind exported output and execution_context to proof commitments."""
    from agentauth.core.hash_util import hash_canonical_json

    issues: list[VerificationIssue] = []

    output = bundle.get("output")
    if output is not None:
        if not isinstance(output, dict):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.OUTPUT_MISMATCH,
                    "bundle output must be a dict when present",
                )
            )
        else:
            expected_output = hash_canonical_json(output)
            if expected_output != proof.output_hash:
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.OUTPUT_MISMATCH,
                        "exported output does not match execution proof output_hash",
                    )
                )

    execution_context = bundle.get("execution_context")
    if execution_context is not None:
        if not isinstance(execution_context, dict):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.CONTEXT_MISMATCH,
                    "execution_context must be a dict when present",
                )
            )
        else:
            expected_context = hash_canonical_json(execution_context)
            if expected_context != proof.context_hash:
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.CONTEXT_MISMATCH,
                        "exported execution_context does not match execution proof context_hash",
                    )
                )

    return issues


def _scitt_section_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    from agentauth.receipts.scitt_bundle import scitt_section_issues

    issues: list[VerificationIssue] = []
    for reason in scitt_section_issues(bundle):
        code = (
            VerifyErrorCode.HPKE_RECIPIENT_MISMATCH
            if "owner_hpke_pk" in reason or "recipient_public_key" in reason
            else VerifyErrorCode.SCITT_INVALID
        )
        issues.append(VerificationIssue(code, reason))
    return issues


def _tool_witness_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    from agentauth.receipts.tool_witness import tool_witnesses_from_bundle, verify_tool_witness

    issues: list[VerificationIssue] = []
    for descriptor in tool_witnesses_from_bundle(bundle):
        for reason in verify_tool_witness(descriptor):
            issues.append(VerificationIssue(VerifyErrorCode.SIGNATURE_INVALID, reason))
    return issues


def _witness_divergence_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    """Flag self-reported tool calls without a matching tool co-sign (SOTA-16e)."""
    from agentauth.receipts.tool_witness import tool_witnesses_from_bundle

    action = bundle.get("action")
    if not isinstance(action, dict) or not action.get("action_name"):
        return []

    side_effect = action.get("side_effect_level")
    if side_effect not in ("bounded_write", "external", "destructive"):
        return []

    tool_witnesses = tool_witnesses_from_bundle(bundle)
    if tool_witnesses:
        return []

    return [
        VerificationIssue(
            VerifyErrorCode.WITNESS_DIVERGENCE,
            "receipt claims a side-effecting tool action but carries no tool co-signature",
        )
    ]


def _audit_inclusion_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    inclusion = bundle.get("audit_inclusion")
    if not inclusion:
        return []

    audit_record = bundle.get("audit_record")
    if not audit_record:
        return [
            VerificationIssue(
                VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                "audit_inclusion requires audit_record for inclusion verification",
            )
        ]
    record_hash = audit_record.get("record_hash")
    proof = inclusion.get("proof")
    checkpoint = inclusion.get("checkpoint")
    if not isinstance(record_hash, str) or not record_hash:
        return [
            VerificationIssue(
                VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                "audit_record.record_hash is missing",
            )
        ]
    if not isinstance(proof, dict) or not isinstance(checkpoint, dict):
        return [
            VerificationIssue(
                VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                "audit_inclusion proof and checkpoint are required",
            )
        ]

    issues: list[VerificationIssue] = []
    allow_unsigned = os.environ.get("AGENT_RECEIPTS_ALLOW_UNSIGNED_CHECKPOINT", "0") == "1"
    log_policy = trusted_audit_log_policy_from_env()
    trust_configured = bool(log_policy["public_keys"] or log_policy["key_ids"])
    checkpoint_valid = True

    if trust_configured:
        for reason in checkpoint_trust_issues(checkpoint):
            checkpoint_valid = False
            issues.append(VerificationIssue(VerifyErrorCode.AUDIT_INCLUSION_INVALID, reason))
    else:
        signature = checkpoint.get("signature")
        if not signature:
            if not allow_unsigned:
                return [
                    VerificationIssue(
                        VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                        "audit checkpoint is unsigned; portable inclusion requires "
                        "a signed checkpoint",
                    )
                ]
        elif not verify(
            {k: v for k, v in checkpoint.items() if k != "signature"},
            signature,
        ):
            return [
                VerificationIssue(
                    VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                    "audit checkpoint signature is invalid",
                )
            ]

    if checkpoint_valid and not AuditChain.verify_inclusion(record_hash, proof, checkpoint):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                "audit inclusion proof does not verify for audit_record.record_hash",
            )
        )
    return issues


def _resolve_audit_log_public_key(bundle: dict[str, Any]) -> str | None:
    """Pinned audit-log Ed25519 public key (hex) carried in-bundle for EV-RT-5."""
    inclusion = bundle.get("audit_inclusion")
    if isinstance(inclusion, dict):
        explicit = inclusion.get("log_public_key")
        if isinstance(explicit, str) and explicit:
            return explicit
        checkpoint = inclusion.get("checkpoint")
        if isinstance(checkpoint, dict):
            signature = checkpoint.get("signature")
            if isinstance(signature, dict):
                public_key = signature.get("public_key")
                if isinstance(public_key, str) and public_key:
                    return public_key
    scitt = bundle.get("scitt")
    if isinstance(scitt, dict):
        service_key = scitt.get("service_public_key")
        if isinstance(service_key, str) and service_key:
            return service_key
    return None


def _audit_record_signature_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    audit_record = bundle.get("audit_record")
    if not isinstance(audit_record, dict):
        return []
    signature = audit_record.get("signature")
    if not isinstance(signature, dict) or not signature:
        return []
    log_key = _resolve_audit_log_public_key(bundle)
    if log_key is None:
        return []
    record_hash = audit_record.get("record_hash")
    if not isinstance(record_hash, str) or not record_hash:
        return [
            VerificationIssue(
                VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                "audit_record.record_hash is missing for signature verification",
            )
        ]
    issues: list[VerificationIssue] = []
    signer_key = signature.get("public_key")
    if signer_key != log_key:
        issues.append(
            VerificationIssue(
                VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                "audit_record.signature public_key does not match pinned log public key",
            )
        )
    elif not verify({"record_hash": record_hash}, signature):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                "audit_record.signature is invalid for the embedded record_hash",
            )
        )
    return issues


def _workload_proof_issues(bundle: dict[str, Any], proof: ExecutionProof) -> list[VerificationIssue]:
    from agentauth.receipts.workload_proof import verify_workload_proof

    section = bundle.get("workload_proof")
    if not section:
        return []
    authority = bundle.get("authority") or {}
    if isinstance(bundle.get("execution_context"), dict):
        auth_ctx = bundle["execution_context"].get("authority")
        if isinstance(auth_ctx, dict):
            authority = auth_ctx
    identity = bundle.get("identity") if isinstance(bundle.get("identity"), dict) else None
    credential_hash_value = None
    if isinstance(identity, dict):
        credential_hash_value = identity.get("credential_hash")
    issues = []
    for reason in verify_workload_proof(
        section,
        proof_id=str(proof.proof_id),
        context_hash=proof.context_hash,
        output_hash=proof.output_hash,
        policy_commitment=proof.policy_commitment,
        credential_hash_value=credential_hash_value,
        presenter_key_hash=authority.get("presenter_key_hash"),
    ):
        issues.append(VerificationIssue(VerifyErrorCode.PROOF_INVALID, reason))
    return issues


def _session_proof_issues(bundle: dict[str, Any], proof: ExecutionProof) -> list[VerificationIssue]:
    from agentauth.receipts.session import verify_bundle_session_proof

    return [
        VerificationIssue(VerifyErrorCode.SESSION_PROOF_INVALID, reason)
        for reason in verify_bundle_session_proof(
            bundle,
            session_id=proof.session_id,
            policy_commitment=proof.policy_commitment,
            output_hash=proof.output_hash,
        )
    ]


def _delegation_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    execution_context = bundle.get("execution_context")
    if not isinstance(execution_context, dict):
        return []
    authorization = execution_context.get("authorization")
    if not isinstance(authorization, dict):
        return []

    delegation_id = authorization.get("delegation_id")
    signed_delegation = authorization.get("signed_delegation")
    if delegation_id is None and signed_delegation is None:
        return []

    if signed_delegation is None:
        return [
            VerificationIssue(
                VerifyErrorCode.DELEGATION_INVALID,
                "authorization references delegation_id but signed_delegation is missing",
            )
        ]
    if not isinstance(signed_delegation, dict):
        return [
            VerificationIssue(
                VerifyErrorCode.DELEGATION_INVALID,
                "signed_delegation must be a dict",
            )
        ]

    from agentauth.core.delegation import (
        delegation_from_envelope,
        verify_delegation_envelope,
    )

    issues: list[VerificationIssue] = []
    for reason in verify_delegation_envelope(signed_delegation):
        issues.append(VerificationIssue(VerifyErrorCode.DELEGATION_INVALID, reason))
    if issues:
        return issues

    try:
        token = delegation_from_envelope(signed_delegation)
    except (KeyError, TypeError, ValueError) as exc:
        return [
            VerificationIssue(
                VerifyErrorCode.DELEGATION_INVALID,
                f"signed delegation document invalid: {exc}",
            )
        ]

    if delegation_id is not None and str(token.delegation_id) != str(delegation_id):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.DELEGATION_INVALID,
                "delegation_id does not match signed delegation document",
            )
        )
    delegation_depth = authorization.get("delegation_depth")
    if delegation_depth is not None and token.depth != int(delegation_depth):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.DELEGATION_INVALID,
                "delegation_depth does not match signed delegation document",
            )
        )
    tool_name = authorization.get("tool_name")
    if isinstance(tool_name, str) and tool_name:
        from agentauth.core.operations import capability_allows, operation_for_mcp_tool

        operation = operation_for_mcp_tool(tool_name)
        if not capability_allows(token.capabilities, operation.resource, operation.action):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.DELEGATION_INVALID,
                    f"signed delegation capabilities do not allow {operation.label()}",
                )
            )
    if not token.is_valid_at():
        issues.append(
            VerificationIssue(
                VerifyErrorCode.DELEGATION_INVALID,
                "delegation token expired or not yet valid",
            )
        )
    return issues


def _stub_proof_issues(proof: ExecutionProof) -> list[VerificationIssue]:
    if os.environ.get("AGENT_RECEIPTS_ALLOW_STUB", "0") == "1":
        return []

    issues: list[VerificationIssue] = []
    blobs: list[bytes] = []
    if proof.bundle.inference_proof:
        blobs.append(proof.bundle.inference_proof)
    if proof.bundle.composed_proof:
        blobs.append(proof.bundle.composed_proof)

    for blob in blobs:
        try:
            data = json.loads(blob)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        attestation = data.get("attestation")
        if isinstance(attestation, str) and attestation.lower() == "stub":
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.STUB_PROOF_NOT_ALLOWED,
                    "stub inference attestation is not allowed in verification",
                )
            )
        inference = data.get("inference")
        if isinstance(inference, dict):
            nested = inference.get("attestation")
            if isinstance(nested, str) and nested.lower() == "stub":
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.STUB_PROOF_NOT_ALLOWED,
                        "composed envelope contains stub inference attestation",
                    )
                )
    return issues


def _certificate_verification_issues(
    bundle: dict[str, Any], proof: ExecutionProof
) -> list[VerificationIssue]:
    cert_raw = bundle.get("certificate")
    if not isinstance(cert_raw, dict) or not cert_raw:
        return []

    try:
        certificate = AgentCertificate.from_dict(cert_raw)
    except (KeyError, TypeError, ValueError) as exc:
        return [
            VerificationIssue(
                VerifyErrorCode.CERTIFICATE_MISMATCH,
                f"invalid certificate block: {exc}",
            )
        ]

    issues: list[VerificationIssue] = []
    expected_ref = certificate_ref_hash(certificate)
    if proof.certificate_ref != expected_ref:
        issues.append(
            VerificationIssue(
                VerifyErrorCode.CERTIFICATE_MISMATCH,
                "certificate_ref does not match recomputed certificate",
            )
        )
    if str(proof.agent_id) != str(certificate.agent_id):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.CERTIFICATE_MISMATCH,
                "proof.agent_id does not match certificate.agent_id",
            )
        )
    if not certificate.is_valid_at(proof.created_at):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.CERTIFICATE_MISMATCH,
                "certificate is not valid at execution proof created_at",
            )
        )
    from agentauth.receipts.certificate import verify_certificate_issuer

    for reason in verify_certificate_issuer(certificate):
        issues.append(VerificationIssue(VerifyErrorCode.CERTIFICATE_MISMATCH, reason))
    issues.extend(_model_provenance_issues(bundle, proof, certificate))
    return issues


def _model_provenance_issues(
    bundle: dict[str, Any],
    proof: ExecutionProof,
    certificate: AgentCertificate,
) -> list[VerificationIssue]:
    """Require certificate model hash to match composed/inference proof envelopes."""
    cert_model = certificate.model_provenance_hash
    issues: list[VerificationIssue] = []

    if proof.bundle.composed_proof:
        from agentauth.receipts.compose import verify_composed_execution_bindings

        for reason in verify_composed_execution_bindings(
            proof.bundle.composed_proof,
            expected_model_provenance_hash=cert_model,
        ):
            issues.append(VerificationIssue(VerifyErrorCode.CERTIFICATE_MISMATCH, reason))

    if proof.bundle.inference_proof and not proof.bundle.composed_proof:
        try:
            inference = json.loads(proof.bundle.inference_proof)
        except json.JSONDecodeError:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.CERTIFICATE_MISMATCH,
                    "inference proof envelope is not valid JSON",
                )
            )
        else:
            inference_model = inference.get("model_provenance_hash")
            if inference_model and inference_model != cert_model:
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.CERTIFICATE_MISMATCH,
                        "inference model_provenance_hash does not match certificate",
                    )
                )

    return issues


def _composed_context_binding_issues(proof: ExecutionProof) -> list[VerificationIssue]:
    if not proof.bundle.composed_proof:
        return []

    from agentauth.receipts.compose import verify_composed_execution_bindings

    issues: list[VerificationIssue] = []
    for reason in verify_composed_execution_bindings(
        proof.bundle.composed_proof,
        expected_context_hash=proof.context_hash,
    ):
        issues.append(VerificationIssue(VerifyErrorCode.CONTEXT_MISMATCH, reason))
    return issues


def compact_receipt_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Strip verbose fields while retaining data required for offline verification."""
    keep = {
        "schema",
        "sdk_version",
        "exported_at",
        "execution_proof",
        "output",
        "execution_context",
        "certificate",
        "decision",
        "authority",
        "action",
        "evidence",
        "session",
        "approval",
        "budget",
        "assurance",
        "policy_violations",
        "verification",
        "signatures",
        "audit_inclusion",
        "audit_record",
        "scitt",
        "mandate",
        "policy",
        "session_proof",
    }
    return {key: bundle[key] for key in keep if key in bundle}


def verify_receipt_bundle(
    bundle: dict[str, Any],
    *,
    min_assurance_tier: str | None = None,
    min_authority_trust_tier: str | None = None,
    require_identity_binding: bool = False,
) -> dict[str, Any]:
    """
    Re-verify a exported receipt bundle (ZK proofs + policy_satisfied flag).

    Does not re-run software policy checks on `output`; partners should treat
    stored violations as the operator attestation at export time.

    Authority binding: `identity_issues` authenticates an embedded identity when one
    is present. When ``require_identity_binding`` is set OR a ``min_assurance_tier`` is
    requested (a relying party asking for an assurance floor), a bundle with no
    *validated* identity binding is rejected with ``AUTHORITY_UNBOUND``.

    ``min_assurance_tier`` thresholds **execution** proof assurance (ZK/TEE/shadow).
    ``min_authority_trust_tier`` thresholds **authority** trust derived from verified
    identity evidence in the authority block (separate from execution assurance).
    """
    issues: list[VerificationIssue] = []

    schema = bundle.get("schema")
    if not is_supported_schema(schema):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.SCHEMA_MISMATCH,
                f"unsupported schema: {schema!r}",
            )
        )
    elif schema == RECEIPT_BUNDLE_SCHEMA_V2:
        for missing in required_sections_present(bundle):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.SCHEMA_MISMATCH,
                    f"missing required v2 section: {missing}",
                )
            )

    proof = execution_proof_from_bundle(bundle)
    issues.extend(_mcp_arguments_hash_issues(bundle))
    issues.extend(_mcp_tool_pin_issues(bundle))
    issues.extend(_monitoring_evidence_issues(bundle))
    issues.extend(_credential_access_issues(bundle))
    issues.extend(_artifact_publication_issues(bundle))
    issues.extend(_anomaly_proof_issues(bundle))
    issues.extend(_output_context_binding_issues(bundle, proof))
    issues.extend(_audit_inclusion_issues(bundle))
    identity_evidence_issues = identity_issues(bundle)
    issues.extend(identity_evidence_issues)
    # A bundle is identity-bound only when it carries an identity section that
    # authenticates cleanly (signature verifies + claims bind to the authority block).
    identity_bound = (
        isinstance(bundle.get("identity"), dict) and not identity_evidence_issues
    )
    workload_proof_issues = _workload_proof_issues(bundle, proof)
    issues.extend(_scitt_section_issues(bundle))
    issues.extend(_tool_witness_issues(bundle))
    issues.extend(_witness_divergence_issues(bundle))
    issues.extend(_session_proof_issues(bundle, proof))
    issues.extend(workload_proof_issues)
    issues.extend(_delegation_issues(bundle))
    issues.extend(_composed_context_binding_issues(proof))
    issues.extend(_stub_proof_issues(proof))
    zk = proof.verify()
    if not zk.get("valid"):
        for reason in zk.get("reasons", ["cryptographic verification failed"]):
            issues.append(VerificationIssue(VerifyErrorCode.PROOF_INVALID, reason))

    if "output" in bundle:
        output_hash = hash_canonical_json(bundle["output"])
        if output_hash != proof.output_hash:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.DECISION_MISMATCH,
                    "output does not match execution proof output_hash",
                )
            )

    execution_context = bundle.get("execution_context")
    if isinstance(execution_context, dict):
        context_hash = hash_canonical_json(execution_context)
        if context_hash != proof.context_hash:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.DECISION_MISMATCH,
                    "execution_context does not match execution proof context_hash",
                )
            )

    stored = bundle.get("verification", {})
    if stored.get("valid") is True and not zk.get("valid"):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.STORED_VERIFICATION_MISMATCH,
                "stored verification disagrees with re-verification",
            )
        )

    decision = bundle.get("decision", {})
    if decision:
        if decision.get("outcome") != proof.decision_outcome.value:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.DECISION_MISMATCH,
                    "decision outcome does not match execution proof",
                )
            )
        if decision.get("authority_version") != proof.authority_version:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.AUTHORITY_MISMATCH,
                    "decision authority_version does not match execution proof",
                )
            )
        if decision.get("session_id") != proof.session_id:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.SESSION_MISMATCH,
                    "decision session_id does not match execution proof",
                )
            )
        decision_obligations = [
            item["type"] if isinstance(item, dict) else str(item)
            for item in list(decision.get("obligations", []))
        ]
        if decision_obligations != list(proof.obligations):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.DECISION_MISMATCH,
                    "decision obligations do not match execution proof",
                )
            )
        if (
            "policy_satisfied" in decision
            and decision.get("policy_satisfied") != proof.policy_satisfied
        ):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.DECISION_MISMATCH,
                    "decision policy_satisfied does not match execution proof",
                )
            )

    authority = bundle.get("authority", {})
    if authority:
        if authority.get("authority_version") != proof.authority_version:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.AUTHORITY_MISMATCH,
                    "authority authority_version does not match execution proof",
                )
            )
        if authority.get("session_id") != proof.session_id:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.SESSION_MISMATCH,
                    "authority session_id does not match execution proof",
                )
            )
        if authority.get("authority_id") and bundle.get("lineage"):
            lineage = bundle["lineage"]
            if lineage.get("authority_id") != authority.get("authority_id"):
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.AUTHORITY_MISMATCH,
                        "lineage authority_id does not match authority block",
                    )
                )
            if lineage.get("authority_version") != authority.get("authority_version"):
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.AUTHORITY_MISMATCH,
                        "lineage authority_version does not match authority block",
                    )
                )
        # EV-RT-2: the top-level `authority` block is a projection of the
        # context-bound `execution_context.authority` (same dict at build time).
        # `execution_context` is covered by `context_hash` above, so requiring
        # equality here transitively binds every authority field: actor_ref,
        # issuer, delegation chain, presenter-key digest, budget refs, approval refs, etc.
        ctx_for_authority = bundle.get("execution_context")
        if isinstance(ctx_for_authority, dict) and isinstance(
            ctx_for_authority.get("authority"), dict
        ):
            # `binding_state` is a build-time annotation on the projection only
            # (the context-bound authority never carries it); it is bound
            # separately below by recomputing it from the bundle evidence.
            authority_sans_annotation = {
                key: value for key, value in authority.items() if key != "binding_state"
            }
            if authority_sans_annotation != ctx_for_authority["authority"]:
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.AUTHORITY_MISMATCH,
                        "authority block does not match the context-bound authority",
                    )
                )

    session = bundle.get("session", {})
    if session and session.get("session_id") != proof.session_id:
        issues.append(
            VerificationIssue(
                VerifyErrorCode.SESSION_MISMATCH,
                "session.session_id does not match execution proof",
            )
        )
    if (
        session
        and "authority_version" in session
        and session.get("authority_version") != proof.authority_version
    ):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.AUTHORITY_MISMATCH,
                "session.authority_version does not match execution proof",
            )
        )

    cert = bundle.get("certificate", {})
    issues.extend(_certificate_verification_issues(bundle, proof))
    if cert.get("policy_commitment") != proof.policy_commitment:
        issues.append(
            VerificationIssue(
                VerifyErrorCode.CERTIFICATE_MISMATCH,
                "certificate policy_commitment does not match proof",
            )
        )

    policy_section = bundle.get("policy", {})
    if isinstance(policy_section, dict):
        policy_commitment = policy_section.get("commitment")
        if policy_commitment is not None and policy_commitment != proof.policy_commitment:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.CERTIFICATE_MISMATCH,
                    "policy.commitment does not match execution proof",
                )
            )
        # EV-RT-2: bind the human-facing policy projection (name/version/tier/
        # capability) to the commitment. `commitment_inputs` is the exact canonical
        # dict the commitment hashes; recompute it (binds numeric_ranges/tools too)
        # and require each projected field to match it. Re-opens P2-28, whose fix
        # only checked `commitment` against the proof, not the readable fields.
        commitment_inputs = policy_section.get("commitment_inputs")
        if isinstance(commitment_inputs, dict):
            if hash_canonical_json(commitment_inputs) != proof.policy_commitment:
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.CERTIFICATE_MISMATCH,
                        "policy.commitment_inputs do not hash to the proof policy_commitment",
                    )
                )
            for field in ("name", "version", "tier", "capability"):
                if field in policy_section and policy_section[field] != commitment_inputs.get(
                    field
                ):
                    issues.append(
                        VerificationIssue(
                            VerifyErrorCode.CERTIFICATE_MISMATCH,
                            f"policy.{field} does not match committed policy inputs",
                        )
                    )

    assurance = enrich_assurance_dict(assurance_from_proof(proof).to_dict())
    binding_state = derive_binding_state(
        bundle,
        identity_bound=identity_bound,
        workload_proof_valid=(
            bundle.get("workload_proof") is not None and not workload_proof_issues
        ),
    )
    assurance["authority_binding_state"] = binding_state
    stored_authority = bundle.get("authority")
    if isinstance(stored_authority, dict):
        stored_binding_state = stored_authority.get("binding_state")
        if stored_binding_state is not None and stored_binding_state != binding_state:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.AUTHORITY_MISMATCH,
                    "authority binding_state does not match the state recomputed "
                    "from bundle evidence",
                )
            )
    if binding_state == BINDING_UNBOUND:
        assurance.setdefault("warnings", []).append(
            "receipt authority is unbound (no verified Clay Seal identity evidence)"
        )
    stored_assurance = stored_assurance_dict(bundle)
    if stored_assurance:
        if stored_assurance.get("level") != assurance["level"]:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.UNSUPPORTED_ASSURANCE,
                    "stored assurance level does not match recomputed assurance",
                )
            )
        stored_tier = stored_assurance.get("tier")
        if stored_tier is not None and stored_tier != assurance.get("tier"):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.UNSUPPORTED_ASSURANCE,
                    "stored assurance tier does not match recomputed assurance",
                )
            )

    if (require_identity_binding or min_assurance_tier is not None) and not identity_bound:
        reason = (
            "receipt has no validated identity binding "
            "(missing or unauthenticated identity evidence); "
        )
        reason += (
            "require_identity_binding is set"
            if require_identity_binding
            else "an assurance tier was requested"
        )
        issues.append(VerificationIssue(VerifyErrorCode.AUTHORITY_UNBOUND, reason))

    if min_assurance_tier is not None:
        try:
            required = parse_trust_tier(min_assurance_tier)
        except ValueError as exc:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.UNSUPPORTED_ASSURANCE,
                    f"invalid min_assurance_tier: {min_assurance_tier!r} ({exc})",
                )
            )
            required = None
        if required is not None:
            actual = parse_trust_tier(assurance["tier"])
            meets = meets_assurance_threshold(actual, required)
            assurance["required_tier"] = required.value
            assurance["required_tier_ordinal"] = tier_ordinal(required)
            assurance["meets_minimum"] = meets
            if not meets:
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.ASSURANCE_THRESHOLD_NOT_MET,
                        (
                            f"execution assurance tier {actual.value!r} "
                            f"(ordinal {tier_ordinal(actual)}) "
                            f"is below required {required.value!r} "
                            f"(ordinal {tier_ordinal(required)})"
                        ),
                    )
                )

    if min_authority_trust_tier is not None:
        from agentauth.core.runtime import AuthorityContext
        from agentauth.receipts.policy_engine import _effective_authority_trust_tier

        authority_raw = None
        execution_context = bundle.get("execution_context")
        if isinstance(execution_context, dict) and isinstance(
            execution_context.get("authority"), dict
        ):
            authority_raw = execution_context["authority"]
        elif isinstance(bundle.get("authority"), dict):
            authority_raw = bundle["authority"]

        if authority_raw is None:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.AUTHORITY_UNBOUND,
                    "min_authority_trust_tier requires an authority block on the receipt",
                )
            )
        else:
            authority_ctx = AuthorityContext.from_dict(authority_raw)
            if identity_bound:
                authority_ctx.evidence_verified = True
            tier_value, tier_issues = _effective_authority_trust_tier(authority_ctx)
            for message in tier_issues:
                issues.append(VerificationIssue(VerifyErrorCode.AUTHORITY_MISMATCH, message))
            try:
                required_auth = parse_trust_tier(min_authority_trust_tier)
            except ValueError as exc:
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.UNSUPPORTED_ASSURANCE,
                        f"invalid min_authority_trust_tier: {min_authority_trust_tier!r} ({exc})",
                    )
                )
                required_auth = None
            if required_auth is not None:
                if tier_value is None:
                    issues.append(
                        VerificationIssue(
                            VerifyErrorCode.AUTHORITY_TRUST_THRESHOLD_NOT_MET,
                            "authority trust tier could not be derived from receipt evidence",
                        )
                    )
                else:
                    actual_auth = parse_trust_tier(tier_value)
                    assurance["authority_trust_tier"] = actual_auth.value
                    assurance["authority_trust_tier_ordinal"] = tier_ordinal(actual_auth)
                    assurance["required_authority_trust_tier"] = required_auth.value
                    assurance["required_authority_trust_tier_ordinal"] = tier_ordinal(
                        required_auth
                    )
                    if not meets_assurance_threshold(actual_auth, required_auth):
                        issues.append(
                            VerificationIssue(
                                VerifyErrorCode.AUTHORITY_TRUST_THRESHOLD_NOT_MET,
                                (
                                    f"authority trust tier {actual_auth.value!r} "
                                    f"(ordinal {tier_ordinal(actual_auth)}) "
                                    f"is below required {required_auth.value!r} "
                                    f"(ordinal {tier_ordinal(required_auth)})"
                                ),
                            )
                        )

    evidence = bundle.get("evidence", {})
    if evidence:
        # EV-RT-3: evidence.summary is fully derivable from the proof — recompute
        # and bind it so the human-facing evidence summary can't be tampered.
        stored_summary = evidence.get("summary")
        if stored_summary is not None:
            from agentauth.receipts.evidence import EvidenceSummary

            if stored_summary != EvidenceSummary.from_proof(proof).to_dict():
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.DECISION_MISMATCH,
                        "evidence.summary does not match the proof-derived summary",
                    )
                )
        # EV-RT-3: evidence.assurance is fully recomputable from the proof — bind
        # the whole block (attestation_path, tee_verified, tier_ordinal, has_*_proof,
        # verification_key_id, …), not just level/tier as the older check did.
        stored_assurance_block = evidence.get("assurance")
        if isinstance(stored_assurance_block, dict):
            recomputed_assurance = enrich_assurance_dict(
                assurance_from_proof(proof).to_dict()
            )
            if stored_assurance_block != recomputed_assurance:
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.UNSUPPORTED_ASSURANCE,
                        "evidence.assurance does not match the proof-derived assurance",
                    )
                )
        stored_record = evidence.get("decision_record", {})
        if stored_record and stored_record.get("outcome") != proof.decision_outcome.value:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.DECISION_MISMATCH,
                    "evidence decision_record outcome does not match execution proof",
                )
            )
        # EV-RT-3: bind the proof-committed decision_record fields and its authority
        # sub-block to the proof / context-bound authority.
        if stored_record:
            if (
                "policy_satisfied" in stored_record
                and stored_record.get("policy_satisfied") != proof.policy_satisfied
            ):
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.DECISION_MISMATCH,
                        "evidence.decision_record.policy_satisfied does not match the proof",
                    )
                )
            record_authority = stored_record.get("authority")
            if isinstance(record_authority, dict):
                if record_authority.get("authority_version") != proof.authority_version:
                    issues.append(
                        VerificationIssue(
                            VerifyErrorCode.AUTHORITY_MISMATCH,
                            "evidence.decision_record.authority_version does not match the proof",
                        )
                    )
                if record_authority.get("session_id") != proof.session_id:
                    issues.append(
                        VerificationIssue(
                            VerifyErrorCode.SESSION_MISMATCH,
                            "evidence.decision_record.session_id does not match the proof",
                        )
                    )
                ctx_auth = bundle.get("execution_context")
                if isinstance(ctx_auth, dict) and isinstance(ctx_auth.get("authority"), dict):
                    if record_authority.get("authority_id") != ctx_auth["authority"].get(
                        "authority_id"
                    ):
                        issues.append(
                            VerificationIssue(
                                VerifyErrorCode.AUTHORITY_MISMATCH,
                                "evidence.decision_record.authority_id does not match "
                                "the context-bound authority",
                            )
                        )
        # EV-RT-2 (decision.*): violations / recommended_action / approval_state are
        # not committed by the proof, so cross-bind the top-level `decision` block to
        # the `evidence.decision_record` mirror. Single-field tampering of either copy
        # now mismatches; the proof anchors outcome/obligations/policy_satisfied.
        if stored_record and decision:
            for field in (
                "violations",
                "recommended_action",
                "approval_state",
                "approval_metadata",
            ):
                if field in decision and field in stored_record:
                    if decision.get(field) != stored_record.get(field):
                        issues.append(
                            VerificationIssue(
                                VerifyErrorCode.DECISION_MISMATCH,
                                f"decision.{field} disagrees with evidence.decision_record",
                            )
                        )
        if stored_record and decision:
            record_obligations = stored_record.get("obligations")
            decision_obligations = decision.get("obligations")
            if (
                record_obligations is not None
                and decision_obligations is not None
                and list(record_obligations) != list(decision_obligations)
            ):
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.DECISION_MISMATCH,
                        "evidence decision_record obligations disagree with decision.obligations",
                    )
                )
            obligation_summary = evidence.get("obligations")
            if obligation_summary and decision_obligations is not None:
                try:
                    from agentauth.core.decision import DecisionResult

                    expected = DecisionResult.from_dict(decision).obligation_section()
                except (KeyError, TypeError, ValueError):
                    expected = None
                if expected is not None and obligation_summary != expected:
                    issues.append(
                        VerificationIssue(
                            VerifyErrorCode.DECISION_MISMATCH,
                            "evidence.obligations summary disagrees with decision obligations",
                        )
                    )

    # EV-RT-3: bind the embedded audit_record. `record_hash` is the canonical hash
    # of {proof_id, execution_proof_hash, action, authorization_context, created_at,
    # prev_hash}; recompute it (binds every content field) and anchor proof_id /
    # execution_proof_hash to THIS bundle's proof. The audit_inclusion check only
    # proves record_hash is in the log — it never tied the record contents to it.
    audit_record = bundle.get("audit_record")
    if isinstance(audit_record, dict) and audit_record.get("record_hash"):
        from agentauth.receipts.audit import execution_proof_hash

        record_body = {
            "proof_id": audit_record.get("proof_id"),
            "execution_proof_hash": audit_record.get("execution_proof_hash"),
            "action": audit_record.get("action"),
            "authorization_context": audit_record.get("authorization_context") or {},
            "created_at": audit_record.get("created_at"),
            "prev_hash": audit_record.get("prev_hash"),
        }
        if hash_canonical_json(record_body) != audit_record.get("record_hash"):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                    "audit_record.record_hash does not match the recomputed record body",
                )
            )
        if audit_record.get("proof_id") != str(proof.proof_id):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                    "audit_record.proof_id does not match execution proof",
                )
            )
        if audit_record.get("execution_proof_hash") != execution_proof_hash(proof):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.AUDIT_INCLUSION_INVALID,
                    "audit_record.execution_proof_hash does not match execution proof",
                )
            )
        issues.extend(_audit_record_signature_issues(bundle))

    stored_violations = policy_violations_from_bundle(bundle)
    top_violations = bundle.get("policy_violations")
    if top_violations is not None and decision:
        if list(top_violations) != list(decision.get("violations", stored_violations)):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.DECISION_MISMATCH,
                    "policy_violations top-level field disagrees with decision.violations",
                )
            )

    budget = bundle.get("budget", {})
    if budget and decision and decision.get("budget_effects") is not None:
        from agentauth.core.decision import DecisionResult

        stored_effects = list(decision.get("budget_effects", []))
        budget_effects = list(budget.get("effects", []))
        if budget_effects and budget_effects != stored_effects:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.DECISION_MISMATCH,
                    "budget.effects disagrees with decision.budget_effects",
                )
            )
        summary = budget.get("summary")
        if summary:
            try:
                from agentauth.core.decision import DecisionResult

                effects_for_summary = budget.get("effects") or decision.get("budget_effects", [])
                merged = dict(decision)
                merged["budget_effects"] = effects_for_summary
                recomputed = DecisionResult.from_dict(merged).budget_summary_dict()
            except (KeyError, TypeError, ValueError):
                recomputed = None
            if recomputed is not None and recomputed != summary:
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.DECISION_MISMATCH,
                        "budget.summary disagrees with recomputed budget effect summary",
                    )
                )

    signatures = bundle.get("signatures", [])
    require_signatures = require_bundle_signatures_from_env()
    signature_status: dict[str, Any] | None = None
    if signatures:
        signer_policy = trusted_signer_policy_from_env()
        signature_status = verify_bundle_signatures(
            bundle,
            trusted_public_keys=signer_policy["public_keys"],
            trusted_key_ids=signer_policy["key_ids"],
        )
        if not signature_status.get("valid"):
            for reason in signature_status.get(
                "reasons", ["envelope signature verification failed"]
            ):
                issues.append(VerificationIssue(VerifyErrorCode.SIGNATURE_INVALID, reason))
    elif require_signatures:
        signer_policy = trusted_signer_policy_from_env()
        signature_status = {
            "valid": False,
            "signed": False,
            "cryptographically_valid": False,
            "trust_configured": bool(signer_policy["public_keys"] or signer_policy["key_ids"]),
            "signers": [],
            "trusted_signers": [],
            "reasons": ["receipt bundle is unsigned; envelope signature is required"],
        }
        issues.append(
            VerificationIssue(
                VerifyErrorCode.SIGNATURE_INVALID,
                "receipt bundle is unsigned; envelope signature is required",
            )
        )

    from agentauth.core.mandate import verify_bundle_mandate

    for reason in verify_bundle_mandate(bundle):
        issues.append(VerificationIssue(VerifyErrorCode.MANDATE_VIOLATION, reason))

    result = verification_result(
        valid=len(issues) == 0,
        issues=issues,
        cryptographic=zk,
        decision={
            "outcome": proof.decision_outcome.value,
            "policy_satisfied": proof.policy_satisfied,
            "authority_version": proof.authority_version,
            "session_id": proof.session_id,
            "obligations": list(proof.obligations),
            "violations": stored_violations,
        },
        assurance=assurance,
    )
    result["schema"] = schema
    if signature_status is not None:
        result["signatures"] = signature_status
    return result


def export_run_result(
    path: str | Path,
    result: RunResult,
    *,
    certificate: AgentCertificate,
    policy: Policy | None = None,
    policy_path: str | Path | None = None,
    context: dict[str, Any] | None = None,
    schema_version: SchemaVersion = "v2",
) -> Path:
    bundle = build_receipt_bundle(
        result,
        certificate=certificate,
        policy=policy,
        policy_path=policy_path,
        context=context,
        schema_version=schema_version,
    )
    return write_receipt_bundle(path, bundle)
