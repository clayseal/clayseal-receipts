"""OCSF ai_operation mapping (Phase 3 BYO audit)."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from agentauth.core.runtime import ActionDescriptor, SideEffectLevel

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.export import build_receipt_bundle
from agentauth.receipts.exporters.ocsf import (
    CLASS_API_ACTIVITY,
    CLASS_DETECTION_FINDING,
    OCSF_SCHEMA_VERSION,
    OcsfExporter,
    bundle_to_api_activity,
    bundle_to_detection_finding,
    bundle_to_ocsf_events,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def bundle() -> dict:
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


@pytest.fixture
def denied_bundle(bundle) -> dict:
    denied = copy.deepcopy(bundle)
    denied["decision"] = dict(denied.get("decision") or {})
    denied["decision"]["outcome"] = "deny"
    denied["decision"]["reasons"] = ["amount exceeds mandate budget"]
    return denied


def _assert_base_event(event: dict, class_uid: int) -> None:
    """The OCSF base-event contract every class shares."""
    assert event["class_uid"] == class_uid
    assert event["type_uid"] == class_uid * 100 + event["activity_id"]
    assert isinstance(event["time"], int)
    assert event["severity_id"] >= 1
    metadata = event["metadata"]
    assert metadata["version"] == OCSF_SCHEMA_VERSION
    assert metadata["profiles"] == ["ai_operation"]
    assert metadata["product"]["vendor_name"] == "Clay Seal"


def test_api_activity_maps_action_and_actor(bundle):
    event = bundle_to_api_activity(bundle)
    _assert_base_event(event, CLASS_API_ACTIVITY)
    assert event["category_uid"] == 6
    assert event["activity_id"] == 3  # bounded_write → Update
    assert event["status_id"] == 1  # allow → Success
    assert event["api"]["operation"] == "payments.refund"
    assert event["api"]["service"]["name"] == "payments"
    assert event["resources"] == [{"type": "transaction", "uid": "txn-1"}]
    assert event["actor"]["app_name"]
    assert event["src_endpoint"]["uid"] == event["actor"]["app_uid"]
    assert event["metadata"]["uid"]  # proof_id
    assert event["metadata"]["correlation_uid"] == "sess-1"
    # ai_model needs a real model identity (name + provider); the dev certificate
    # only has a provenance hash, which stays in unmapped.
    assert "ai_model" not in event
    assert event["unmapped"]["agent_receipts"]["model_provenance_hash"]


def test_api_activity_carries_owasp_decision_fields(bundle):
    unmapped = bundle_to_api_activity(bundle)["unmapped"]["agent_receipts"]
    assert unmapped["action_classification"] == "bounded_write"
    assert unmapped["authorization_outcome"] == "allow"
    assert unmapped["policy_commitment"]
    assert unmapped["session_id"] == "sess-1"


def test_allow_produces_no_detection_finding(bundle):
    assert bundle_to_detection_finding(bundle) is None
    assert len(bundle_to_ocsf_events(bundle)) == 1


def test_denial_produces_detection_finding(denied_bundle):
    events = bundle_to_ocsf_events(denied_bundle)
    assert len(events) == 2
    activity, finding = events
    assert activity["status_id"] == 2  # deny → Failure
    assert activity["api"]["response"]["error"] == "deny"
    assert "mandate budget" in activity["api"]["response"]["error_message"]
    _assert_base_event(finding, CLASS_DETECTION_FINDING)
    assert finding["category_uid"] == 2
    assert finding["finding_info"]["types"] == ["Policy Violation"]
    assert "deny" in finding["finding_info"]["title"]
    assert "mandate budget" in finding["finding_info"]["desc"]


def test_exporter_posts_events(denied_bundle):
    class _Client:
        def __init__(self):
            self.calls = []

        def post(self, url, **kwargs):
            self.calls.append({"url": url, **kwargs})

            class R:
                status_code = 200

                def raise_for_status(self):
                    pass

            return R()

    client = _Client()
    result = OcsfExporter(endpoint="https://8.8.8.8/ocsf", client=client).export(
        denied_bundle
    )
    assert result["delivered"] is True
    assert result["ocsf_version"] == OCSF_SCHEMA_VERSION
    assert len(client.calls[0]["json"]) == 2
