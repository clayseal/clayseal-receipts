"""The receipts/proofs engine: issue identity, authorize actions, build proofs.

This is where all four agent-receipts layers meet:
  L1 identity   -> AgentAuth.identify (embedded backend) mints a JWT-SVID
  L2 capability -> a Biscuit scoped to the mandate; session.authorize() (PoP)
  L3 receipts   -> AgentWrapper.record() per action -> ExecutionProof + audit chain
  L4 ZK proof   -> mode="prove", prove_policy=True -> real Halo2 policy proof

There is no diff parsing. The capability token decides allow/deny; the policy
engine (driven by the same capability grant via the AuthorityBinding) gates the
proof; a denied action produces no allow-proof.
"""

from __future__ import annotations

import json
from typing import Any

from agentauth.receipts import signing
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.export import build_receipt_bundle
from agentauth.receipts.policy import Policy
from agentauth.receipts.proof import DecisionOutcome
from agentauth.receipts.prover import verify_structural_policy
from agentauth.receipts.integration import wrap_agentauth_session
from agentauth.core.runtime import ActionDescriptor, SideEffectLevel
from agentauth.core.signing import SigningKey

import config
from mandate import Mandate
from sessions import SessionEntry

SESSION_RECEIPT_SCHEMA = "agentauth-mcp.session-receipt.v1"

# The wrapped "model" is never invoked: record() takes a precomputed output.
_NOOP_MODEL = lambda _inp: {}  # noqa: E731


def make_wrapper(agent_session: Any, *, policy: Policy, audit_db: str) -> Any:
    """Build a prove-mode AgentWrapper bound to this attested identity.

    session.wrap() injects the AuthorityBinding (from the credential's capabilities)
    and wires capability_authorizer=session.authorize. mode="prove" requires an
    explicit certificate; dev_certificate's default model hash matches the wrapper's.
    """
    certificate = dev_certificate(
        policy.commitment(),
        organization=config.TENANT_ORG,
        principal_id=config.SERVER_NAME,
    )
    return wrap_agentauth_session(agent_session,
        _NOOP_MODEL,
        policy=policy,
        mode="prove",
        prove_policy=True,
        prove_composed=False,  # policy-only Halo2; no inference/composed backend
        certificate=certificate,
        audit_db=audit_db,
    )


def _action_descriptor(resource: str, action: str) -> ActionDescriptor:
    return ActionDescriptor(
        action_name=action,
        action_category="code_change",
        resource_type="repo_file",
        resource_ref=resource,
        side_effect_level=SideEffectLevel.BOUNDED_WRITE,
    )


def authorize_and_record(
    entry: SessionEntry,
    *,
    resource: str,
    action: str,
    policy: Policy,
    gate_key: SigningKey,
    signed_mandate: dict[str, Any],
) -> dict[str, Any]:
    """Authorize one action via the capability token and record a receipt.

    Returns a SANITIZED result for the agent: {allowed, reason, receipt_id}.
    On allow, a real Halo2 policy proof is attached and a signed bundle is stored.
    """
    authz = entry.agent_session.authorize(resource, action)  # Biscuit + PoP (L2)
    allowed = bool(authz.get("allowed"))
    descriptor = _action_descriptor(resource, action)

    if allowed:
        output = {"decision": "allow", "decision_risk": 0.0}
        outcome = DecisionOutcome.ALLOW
        extra_violations = None
    else:
        output = {"decision": "deny", "decision_risk": 1.0}
        outcome = DecisionOutcome.DENY
        extra_violations = ["out_of_authorized_scope"]

    result = entry.wrapper.record(
        action=descriptor,
        context={
            "input": {"resource": resource, "operation": action},
            "authorization": authz,
            "touched_resources": [resource],
        },
        output=output,
        decision_outcome=outcome,
        extra_violations=extra_violations,
    )

    bundle = build_receipt_bundle(
        result,
        certificate=entry.wrapper.certificate,
        policy=policy,
        audit_chain=entry.wrapper.audit,
    )
    # Embed the human authorization (its own schema differs from the SDK's native
    # signed_mandate slot) and sign the whole receipt with the trusted gate key.
    bundle["human_authorization"] = signed_mandate
    signing.sign_bundle(bundle, gate_key, role="gate")

    receipt_id = str(result.proof.proof_id)
    entry.receipts.append(
        {
            "receipt_id": receipt_id,
            "resource": resource,
            "action": action,
            "decision": result.decision.outcome.value,
            "attestation_path": result.proof.attestation_path.value,
            "bundle": bundle,
        }
    )

    # Sanitized: never echo the raw biscuit reason or denylist internals.
    reason = "authorized — in scope" if allowed else "denied — outside your authorized scope"
    return {"allowed": allowed, "reason": reason, "receipt_id": receipt_id}


def finalize_session_bundle(
    entry: SessionEntry,
    *,
    mandate: Mandate,
    gate_key: SigningKey,
    signed_mandate: dict[str, Any],
) -> dict[str, Any]:
    """Aggregate the session's receipts into one signed manifest for CI.

    `authorized` = allow receipts (each carries a Halo2 policy proof). `denied` =
    attempted out-of-scope actions (no proof), included for transparency.
    """
    authorized = [r for r in entry.receipts if r["decision"] == "allow"]
    denied = [r for r in entry.receipts if r["decision"] != "allow"]

    manifest: dict[str, Any] = {
        "schema": SESSION_RECEIPT_SCHEMA,
        "session": entry.token,
        "mandate_id": entry.mandate_id,
        "agent_actor": entry.agent_actor,
        "issue_ref": entry.issue_ref,
        "created_at": entry.created_at,
        "agent_id": entry.agent_session.agent_id,
        "spiffe_id": getattr(entry.agent_session.credential, "spiffe_id", None),
        "authorized": [
            {
                "resource": r["resource"],
                "action": r["action"],
                "receipt_id": r["receipt_id"],
                "attestation_path": r["attestation_path"],
                "receipt": r["bundle"],
            }
            for r in authorized
        ],
        "denied": [
            {"resource": r["resource"], "action": r["action"], "receipt_id": r["receipt_id"]}
            for r in denied
        ],
        "human_authorization": signed_mandate,
    }
    signing.sign_bundle(manifest, gate_key, role="gate")

    config.ensure_dirs()
    out_path = config.RECEIPTS_DIR / f"{entry.token}.json"
    out_path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")

    receipt_commit_path = config.RECEIPT_COMMIT_PATH_TEMPLATE.format(session=entry.token)
    return {
        "receipt_ref": receipt_commit_path,
        "operator_path": str(out_path),
        "authorized_count": len(authorized),
        "denied_count": len(denied),
        "bundle": manifest,
    }


def self_check_bundle(bundle: dict[str, Any], *, gate_key: SigningKey) -> dict[str, Any]:
    """Best-effort local verification used in tests: gate signature + each policy proof."""
    sig = signing.verify_bundle_signatures(bundle, trusted_key_ids={gate_key.key_id})
    proof_results = []
    for item in bundle.get("authorized", []):
        receipt = item.get("receipt", {})
        proof_b64 = (
            receipt.get("execution_proof", {})
            .get("bundle", {})
            .get("policy_proof_b64")
        )
        if proof_b64:
            import base64

            proof_results.append(verify_structural_policy(base64.b64decode(proof_b64)))
    return {"signatures": sig, "policy_proofs": proof_results}
