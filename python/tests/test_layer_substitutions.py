from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.capabilities.identity_adapters import get_identity_provider

from agentauth.receipts import Policy
from agentauth.receipts.integration import wrap_with_identity_session, wrap_with_provider_claims


def _policy() -> Policy:
    return Policy.from_dict(
        {
            "version": 1,
            "name": "substitution-test",
            "tier": "structural",
            "capability": "operator_attested",
        }
    )


@dataclass
class DummyCapabilityLayer:
    name: str = "dummy-l2"

    def issue_commit_token(self, ctx: Any, *, key: Any, ttl_seconds: int) -> dict[str, Any]:
        return {"ctx": ctx, "ttl_seconds": ttl_seconds}

    def verify_commit_token(self, signed: Any, *, ctx: Any) -> tuple[bool, str | None]:
        return (signed.get("ctx") == ctx, None)

    def compile_task_scope(self, mandate: dict[str, Any]) -> dict[str, Any]:
        return {"compiled": mandate}


def test_l3_wraps_oidc_claims_without_agentauth_l1(tmp_path):
    agent = wrap_with_provider_claims(
        lambda inp: {"ok": True, **inp},
        _policy(),
        "oidc",
        {"sub": "agent-1", "iss": "https://issuer.example", "scope": "tool:call"},
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    result = agent.run({"x": 1})

    assert result.output["ok"] is True
    assert result.execution_context.authority.authority_id == "agent-1"


def test_l3_accepts_substituted_capability_layer_metadata(tmp_path):
    session = get_identity_provider("spiffe_jwt").build_session(
        {
            "sub": "spiffe://example.org/customer/ten_demo/agent/bot/xyz",
            "iss": "spiffe://example.org",
            "scope": "tool:call",
        }
    )
    agent = wrap_with_identity_session(
        lambda inp: {"ok": True, **inp},
        _policy(),
        session,
        capability_layer=DummyCapabilityLayer(),
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert session.metadata["capability_layer"] == "dummy-l2"
    assert agent.run({"x": 2}).output["ok"] is True


def test_l3_wraps_azure_and_gcp_provider_claims(tmp_path):
    azure = wrap_with_provider_claims(
        lambda inp: {"ok": True, **inp},
        _policy(),
        "azure_ad",
        {"oid": "obj-123", "tid": "tenant-123", "scp": "api.read"},
        mode="shadow",
        audit_db=str(tmp_path / "azure.sqlite"),
    )
    gcp = wrap_with_provider_claims(
        lambda inp: {"ok": True, **inp},
        _policy(),
        "gcp_service_account",
        {"email": "agent@project.iam.gserviceaccount.com", "project_id": "project-1"},
        mode="shadow",
        audit_db=str(tmp_path / "gcp.sqlite"),
    )

    assert azure.run({"x": 3}).execution_context.authority.authority_id == "obj-123"
    assert (
        gcp.run({"x": 4}).execution_context.authority.authority_id
        == "agent@project.iam.gserviceaccount.com"
    )
