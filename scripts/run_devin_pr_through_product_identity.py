#!/usr/bin/env python3
"""Run the Devin attack matrix through the FULL product: attested identity + a
real signed Mandate bound into every receipt.

Extends `run_devin_pr_through_product.py` (which ran the receipts runtime unbound,
against the demo's `human_authorization.v1` envelope) by adding the two pieces
that were the open gaps:

  * L1/L2 identity seam — boots the real FastAPI identity backend in-process,
    `AgentAuth().identify(...)` mints an attested JWT-SVID, and
    `session.wrap(...)` binds that SPIFFE identity into every receipt's authority.
  * real `Mandate` — `issue_mandate(...)` signs a grant (delegate = the attested
    SPIFFE id), bound into the bundle and checked by `verify_bundle_mandate(...)`.

So each receipt now carries: the attested agent identity, a signed human mandate,
the real DecisionResult, a v2 bundle, and a hash-chained audit entry.

    python3.11 scripts/run_devin_pr_through_product_identity.py
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
for p in (str(ROOT), str(SCRIPTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

# Isolate backend state BEFORE importing the app (mirrors the SDK conftest).
_TMP = tempfile.mkdtemp(prefix="devin-product-identity-")
os.environ.setdefault("AGENTAUTH_DATABASE_URL", f"sqlite:///{_TMP}/agents.db")

import uvicorn  # noqa: E402

from agentauth import AgentAuth  # noqa: E402
from agentauth.backend.main import app  # noqa: E402
from agentauth.receipts import Policy, build_receipt_bundle, verify_receipt_bundle  # noqa: E402
from agentauth.capabilities.mandate import (  # noqa: E402
    check_receipt_against_mandate,
    issue_mandate,
    verify_bundle_mandate,
)
from agentauth.core.runtime import ActionDescriptor  # noqa: E402
from agentauth.core.signing import load_or_create_key  # noqa: E402

# Authority model is resource:action. The action carries resource_type="repo" and
# verb "gate"; the agent scope "repo:gate" authorizes exactly that.
ACTION = ActionDescriptor(action_name="repo.gate", resource_type="repo")

# Reuse the attack payloads + decision computation from the sibling script.
from run_devin_pr_through_product import (  # noqa: E402
    HARDENED_POLICY,
    build_repo,
    compute_pr_reasons,
    payload_audit_removal,
    payload_auth_edit,
    payload_benign,
    payload_semantic_bypass,
    payload_slowdrip,
    seam_baseline,
)


def boot_backend() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("identity backend failed to start")
    return f"http://127.0.0.1:{port}"


def main() -> int:
    base_url = boot_backend()
    tenant = AgentAuth.create_tenant("Devin PR Gate Demo", base_url=base_url)
    auth = AgentAuth(api_key=tenant["api_key"], base_url=base_url, dev_attestation=True)

    # L1/L2: attest the gate workload -> short-lived JWT-SVID + SPIFFE identity.
    # Scope "repo:gate" authorizes the resource:action the receipt records (the
    # ACTION below), so the attested authority is permitted to perform it.
    agent = auth.identify(
        agent_type="devin-pr-gate", owner="maintainer@demo.org",
        scopes=["repo:gate"],
    )
    spiffe_id = agent.credential.spiffe_id
    print(f"Attested agent identity (SPIFFE): {spiffe_id}\n")

    policy = Policy.from_dict(
        {
            "version": 1,
            "name": "devin-pr-gate",
            "tier": "structural",
            "capability": "operator_attested",
        }
    )
    human_key = load_or_create_key(Path(_TMP) / "human_maintainer.ed25519.pem")
    log_key = load_or_create_key(Path(_TMP) / "audit_log.ed25519.pem")
    audit_db = Path(_TMP) / "chain.sqlite"

    # A real signed human Mandate, issued BEFORE any action (so issued_at precedes
    # each receipt's created_at), delegated to the attested agent identity.
    from agentauth.capabilities.mandate import Mandate

    mandate_env = issue_mandate(
        issuer=human_key.public_key_hex,  # issuer must be bound to the signing key
        key=human_key,
        delegate=spiffe_id,
        allowed_actions=["repo.gate"],
        allowed_resources=["repo"],
        ttl_seconds=3600,
    )
    mandate_obj = Mandate.from_dict(mandate_env["document"])

    parser_scope = ["swe_triage/parser.py", "tests/test_parser.py"]
    cases = [
        ("benign in-scope PR (control)", payload_benign, None, "allow"),
        ("out-of-scope auth.py edit (#1)", payload_auth_edit, None, "deny"),
        ("D1/I2/L1 in-scope auth removal", payload_semantic_bypass, None, "deny"),
        ("A4 audit-log suppression", payload_audit_removal, None, "deny"),
        ("G1 slow-drip (seam->True)", payload_slowdrip, seam_baseline, "deny"),
    ]

    all_ok = True
    for label, payload, baseline_patch, expected in cases:
        repo, base, head, demo_mandate = build_repo(
            payload, allowed_paths=parser_scope, denied_paths=["swe_triage/auth.py"],
            baseline_patch=baseline_patch,
        )
        try:
            import json

            reasons, _ = compute_pr_reasons(
                repo, base=base, head=head,
                authorization_envelope=json.loads(demo_mandate.read_text(encoding="utf-8")),
                policy=json.loads(HARDENED_POLICY.read_text(encoding="utf-8")),
                github_actor="devin-ai-integration[bot]",
            )
            violations = [f"{r['code']}: {r['message']}" for r in reasons]

            # L3/L4 bound to the attested identity via the session seam.
            receipted = agent.wrap(
                lambda inp: inp, policy=policy, mode="shadow", audit_db=str(audit_db)
            )
            receipted.audit.signing_key = log_key
            output = {"decision": "deny" if reasons else "allow", "violation_count": len(reasons)}
            result = receipted.record(
                action=ACTION,
                context={"input": {"repo": str(repo), "base": base, "head": head}},
                output=output,
                extra_violations=violations,
            )

            bundle = build_receipt_bundle(
                result, certificate=receipted.certificate, policy=policy,
                audit_chain=receipted.audit, signed_mandate=mandate_env,
            )

            mandate_issues = verify_bundle_mandate(bundle)
            action_issues = check_receipt_against_mandate(
                mandate_obj,
                action=result.execution_context.action,
                decision=result.decision,
                at=datetime.now(timezone.utc),
            )
            verification = verify_receipt_bundle(bundle)
            bound_id = bundle["authority"]["subject_id"]
        finally:
            import shutil

            shutil.rmtree(repo, ignore_errors=True)

        ok = result.decision_outcome.value == expected and not mandate_issues and not action_issues
        all_ok = all_ok and ok
        mark = "✓" if ok else "✗"
        print(f"### {label}  {mark}")
        print(f"  real-engine decision     : {result.decision_outcome.value} (expected {expected})")
        print(f"  receipt authority (id)   : {bound_id}")
        print(f"  identity == attested     : {bound_id == spiffe_id}")
        print(f"  mandate binding valid    : {not mandate_issues}  {mandate_issues or ''}")
        print(f"  action within mandate    : {not action_issues}  {action_issues or ''}")
        print(f"  bundle has mandate sect. : {'mandate' in bundle}")
        print(f"  verify_receipt_bundle    : valid={verification.get('valid')} ({verification.get('reasons')})")
        print()

    auth.close()
    print(f"{'ALL CASES MATCHED' if all_ok else 'SOME CASES FAILED'}: full product path —")
    print("attested SPIFFE identity + signed Mandate bound into every real v2 receipt,")
    print("adjudicated by the real engine and hash-chained in one signed audit log.")
    print("\n(verify_receipt_bundle still valid=False under shadow: ZK proof bytes need the")
    print("Rust proving backend — identity & mandate binding are now real and verified.)")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
