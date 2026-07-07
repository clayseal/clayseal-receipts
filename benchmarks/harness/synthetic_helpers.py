from __future__ import annotations

import copy
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from agentauth.receipts import AgentWrapper
from agentauth.core.authority_binding import AuthorityBinding
from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle

from harness.agent_setup import apply_agent_policy
from harness.pipeline import fraud_policy
from harness.synthetic_backend import create_tenant_client, identify_agent


def identity_section_for_session(client: Any, session: Any) -> dict[str, Any]:
    from agentauth.receipts.identity_evidence import build_identity_section

    credential = session.credential
    jwks = client._http.get("/v1/jwks.json")
    return build_identity_section(
        {
            "token": credential.token,
            "spiffe_id": credential.spiffe_id,
            "bound_keyhash": credential.bound_keyhash,
            "biscuit": credential.biscuit,
            "biscuit_root_public_key": credential.biscuit_root_public_key,
            "expires_at": credential.expires_at,
        },
        jwks,
    )


def export_identity_receipt(
    agent: Any,
    *,
    client: Any,
    session: Any,
    transaction_id: str = "syn-identity",
    attach_tee: bool = True,
) -> tuple[Any, dict[str, Any]]:
    """Run a minimal fraud action and export a bundle with embedded JWT-SVID evidence."""
    import base64

    from agentauth.receipts.proof import AttestationPath
    from agentauth.receipts.tee import TeeQuote, TeeQuoteFormat

    from harness.nitro_fixture import build_test_nitro_quote, process_nitro_quote_bytes, process_nitro_root_pem

    policy = fraud_policy()
    apply_agent_policy(agent, policy)
    binding = AuthorityBinding.from_agentauth_credential(session.credential.to_binding_dict())
    audit_path = Path(tempfile.mkdtemp(prefix="syn-audit-")) / "audit.sqlite"
    wrapper = AgentWrapper(
        lambda _inp: {"decision": "approve", "fraud_score": 0.05},
        policy,
        certificate=agent.certificate,
        default_authority_binding=binding,
        mode="bounded_auto",
        audit_db=str(audit_path),
    )
    run_result = wrapper.run(
        {"transaction_id": transaction_id, "amount": 10.0},
        session_id=f"syn-{session.agent_id}",
    )
    identity = identity_section_for_session(client, session)
    if attach_tee:
        process_nitro_root_pem()
        document = process_nitro_quote_bytes()
        run_result.proof.attestation_path = AttestationPath.TEE_HYBRID
        run_result.proof.bundle.tee_quote = TeeQuote(
            format=TeeQuoteFormat.NITRO_ENCLAVE_V1,
            quote_b64=base64.standard_b64encode(document).decode("ascii"),
            max_age_seconds=None,
        ).to_dict()
        # TEE is attached after the run; drop audit linkage that no longer matches proof hash.
        run_result.audit_record = None
    with allow_stub_proofs():
        bundle = build_receipt_bundle(
            run_result,
            certificate=wrapper.certificate,
            policy=policy,
            identity=identity,
        )
    return run_result, bundle


def issue_session(
    tenant_slug: str,
    *,
    agent_type: str,
    owner: str,
) -> tuple[Any, Any]:
    client = create_tenant_client(tenant_slug)
    session = identify_agent(client, agent_type=agent_type, owner=owner)
    return client, session


@contextmanager
def allow_stub_proofs() -> Iterator[None]:
    env = {
        "AGENT_RECEIPTS_ALLOW_STUB": "1",
        "AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE": "1",
        "AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES": "0",
    }
    previous = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def nitro_test_root(pem_path: str) -> Iterator[None]:
    previous = os.environ.get("AGENT_RECEIPTS_NITRO_ROOT_PEM")
    os.environ["AGENT_RECEIPTS_NITRO_ROOT_PEM"] = pem_path
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("AGENT_RECEIPTS_NITRO_ROOT_PEM", None)
        else:
            os.environ["AGENT_RECEIPTS_NITRO_ROOT_PEM"] = previous


def attach_mock_tee_quote(
    run_result: Any,
    *,
    pem_path: str,
    certificate: Any,
) -> dict[str, Any]:
    import base64

    from agentauth.receipts.proof import AttestationPath
    from agentauth.receipts.tee import TeeQuote, TeeQuoteFormat

    from harness.nitro_fixture import build_test_nitro_quote

    document, _root = build_test_nitro_quote()
    run_result.proof.attestation_path = AttestationPath.TEE_HYBRID
    run_result.proof.bundle.tee_quote = TeeQuote(
        format=TeeQuoteFormat.NITRO_ENCLAVE_V1,
        quote_b64=base64.standard_b64encode(document).decode("ascii"),
        max_age_seconds=None,
    ).to_dict()
    with nitro_test_root(pem_path):
        bundle = build_receipt_bundle(
            run_result,
            certificate=certificate,
            policy=fraud_policy(),
        )
    return bundle


def verify_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    with allow_stub_proofs():
        return verify_receipt_bundle(bundle)


def tamper_bundle(bundle: dict[str, Any], *, path: str, value: Any) -> dict[str, Any]:
    """Return a deep-copied bundle with one injected mutation."""
    mutated = copy.deepcopy(bundle)
    parts = path.split(".")
    node = mutated
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
    return mutated
