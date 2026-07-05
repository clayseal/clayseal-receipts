"""OTel GenAI semantic-convention mapping for receipts (SOTA-13)."""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.export import build_receipt_bundle
from agentauth.receipts.otel import receipt_to_otel_attributes, receipt_to_otel_events, receipt_to_otel_log_record
from agentauth.core.runtime import ActionDescriptor, SideEffectLevel

ROOT = Path(__file__).resolve().parents[2]


def _bundle():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run(
        {"transaction_id": "t1", "amount": 10.0},
        action=ActionDescriptor(
            action_name="payments.refund",
            action_category="payments",
            resource_type="transaction",
            resource_ref="txn-1",
            side_effect_level=SideEffectLevel.BOUNDED_WRITE,
        ),
        session_id="sess-1",
    )
    return build_receipt_bundle(result, certificate=cert, policy=policy)


def test_maps_action_to_gen_ai_attributes():
    attrs = receipt_to_otel_attributes(_bundle())
    assert attrs["gen_ai.system"] == "agent_receipts"
    assert attrs["gen_ai.operation.name"] == "execute_tool"
    assert attrs["gen_ai.tool.name"] == "payments.refund"
    assert attrs["gen_ai.tool.type"] == "payments"
    assert attrs["gen_ai.conversation.id"] == "sess-1"


def test_maps_receipt_specific_evidence_namespaced():
    attrs = receipt_to_otel_attributes(_bundle())
    assert attrs["agent_receipts.action.resource_ref"] == "txn-1"
    assert attrs["agent_receipts.action.side_effect_level"] == "bounded_write"
    assert attrs["agent_receipts.decision.outcome"] == "allow"
    assert attrs["agent_receipts.receipt.schema"].startswith("https://") or attrs[
        "agent_receipts.receipt.schema"
    ]
    assert attrs["agent_receipts.receipt.proof_id"]


def test_omits_missing_fields_and_shapes_log_record():
    # A near-empty bundle should not raise and should still carry the system tag.
    attrs = receipt_to_otel_attributes({"action": {"action_name": "x"}})
    assert attrs["gen_ai.tool.name"] == "x"
    assert "gen_ai.conversation.id" not in attrs  # absent, not None

    record = receipt_to_otel_log_record(_bundle())
    assert record["body"] == "agent.receipt"
    assert record["attributes"]["gen_ai.tool.name"] == "payments.refund"


def test_tool_io_events_and_otlp_shape():
    bundle = _bundle()
    bundle["execution_context"] = {
        "tool_input": {"amount": 10},
        "tool_output": {"status": "ok"},
    }
    events = receipt_to_otel_events(bundle)
    names = {event["name"] for event in events}
    assert "gen_ai.tool.input" in names
    assert "gen_ai.tool.output" in names

    from agentauth.receipts.otel import bundle_to_otlp_resource_logs

    otlp = bundle_to_otlp_resource_logs(bundle)
    assert otlp["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["events"]


def test_siem_otel_includes_gen_ai_attributes():
    from agentauth.receipts.compliance import export_siem_otel

    otel = export_siem_otel(_bundle())
    assert otel["attributes"]["gen_ai.tool.name"] == "payments.refund"
    assert otel["attributes"]["agent.receipt.proof_id"]
    assert otel["events"]
