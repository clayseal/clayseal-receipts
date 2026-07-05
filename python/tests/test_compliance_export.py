"""SOTA-4: compliance profile mapping and SIEM export tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.auditor import auditor_evidence_summary
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.compliance import (
    export_compliance_mapped,
    export_siem_cef,
    export_siem_ecs,
    export_siem_otel,
    export_siem_record,
    load_compliance_profile,
)
from agentauth.receipts.export import build_receipt_bundle, export_bundle_for_audience
from agentauth.capabilities.mandate import issue_mandate
from agentauth.core.signing import generate_keypair
from agentauth.receipts.witness import add_witness_cosignature

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def shadow_bundle():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0}, session_id="sess-1")
    return build_receipt_bundle(result, certificate=cert, policy=policy)


@pytest.mark.parametrize("profile", ["eu-ai-act", "soc2", "iso27001"])
def test_compliance_profile_required_fields_complete(shadow_bundle, profile):
    mapped = export_compliance_mapped(shadow_bundle, profile)
    assert mapped["profile"] == profile
    assert mapped["completeness"]["complete"] is True
    assert mapped["completeness"]["missing_fields"] == []
    assert mapped["fields"]["policy_reference"]["present"] is True
    assert mapped["fields"]["input_commitment"]["present"] is True
    assert mapped["fields"]["output_commitment"]["present"] is True
    assert mapped["fields"]["automated_reasoning"]["present"] is True
    assert mapped["fields"]["integrity_protection"]["present"] is True


def test_load_compliance_profile_documents():
    doc = load_compliance_profile("eu-ai-act")
    assert doc["profile"] == "eu-ai-act"
    assert doc["required_fields"]


def test_export_bundle_for_audience_profile_mode(shadow_bundle):
    mapped = export_bundle_for_audience(shadow_bundle, profile="soc2")
    assert mapped["profile"] == "soc2"
    assert "controls" in mapped


def test_auditor_summary_profile_shortcut(shadow_bundle):
    mapped = auditor_evidence_summary(shadow_bundle, profile="iso27001")
    assert mapped["completeness"]["complete"] is True


def test_siem_ecs_uses_live_verification(shadow_bundle):
    shadow_bundle["verification"] = {"valid": True}
    ecs = export_siem_ecs(shadow_bundle)
    assert ecs["@timestamp"]
    assert ecs["agent_receipts"]["proof_id"]
    assert ecs["agent_receipts"]["verification_valid"] is False
    assert ecs["agent_receipts"]["stored_verification_valid"] is True


def test_siem_otel_record_shape(shadow_bundle):
    otel = export_siem_otel(shadow_bundle)
    assert otel["body"]
    assert otel["attributes"]["agent.receipt.proof_id"]
    assert otel["resource"]["service.name"] == "agent-receipts"


def test_siem_cef_single_line(shadow_bundle):
    cef = export_siem_cef(shadow_bundle)
    assert cef.startswith("CEF:0|Agent Receipts|Receipt|")
    assert "proofId=" in cef
    assert "outcome=allow" in cef


def test_export_siem_record_dispatch(shadow_bundle):
    assert isinstance(export_siem_record(shadow_bundle, format="cef"), str)
    assert isinstance(export_siem_record(shadow_bundle, format="ecs"), dict)


def test_ecs_fixture_parses_like_siem_ingest(shadow_bundle, tmp_path):
    ecs = export_siem_ecs(shadow_bundle)
    fixture_path = tmp_path / "ecs_ingest_sample.json"
    fixture_path.write_text(json.dumps(ecs, indent=2) + "\n", encoding="utf-8")

    loaded = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert loaded["agent_receipts"]["proof_id"] == ecs["agent_receipts"]["proof_id"]
    assert loaded["event.outcome"] == ecs["event.outcome"]
    assert loaded["hash.sha256"] == ecs["hash.sha256"]


def test_audit_summary_siem_cli_path(shadow_bundle):
    record = auditor_evidence_summary(shadow_bundle, siem_format="ecs")
    assert isinstance(record, dict)
    assert "agent_receipts" in record


def test_siem_exports_include_verified_extension_fields(monkeypatch):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    log_key = generate_keypair()
    witness_key = generate_keypair()
    agent.audit.signing_key = log_key
    mandate_key = generate_keypair()
    signed_mandate = issue_mandate(
        issuer=mandate_key.public_key_hex,
        key=mandate_key,
        allowed_actions=["agent.run"],
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0}, session_id="sess-1")
    bundle = build_receipt_bundle(
        result,
        certificate=cert,
        policy=policy,
        audit_chain=agent.audit,
        signed_mandate=signed_mandate,
    )
    checkpoint = bundle["audit_inclusion"]["checkpoint"]
    add_witness_cosignature(checkpoint, witness_key, allow_unsafe=True)
    bundle["session_proof"] = {"mode": "folded", "digest": "abc123"}
    bundle["execution_proof"]["bundle"]["verification_key_id"] = "vk-recursive"
    bundle["execution_proof"]["bundle"]["composed_proof_b64"] = "Y29tcG9zZWQ="
    bundle["execution_proof"]["bundle"]["tee_quote"] = {
        "kind": "nitro",
        "eat_nonce": "nonce-1",
    }

    from agentauth.receipts import export as export_module

    monkeypatch.setattr(
        export_module,
        "verify_receipt_bundle",
        lambda _bundle, **_kwargs: {"valid": True, "issues": []},
    )

    ecs = export_siem_ecs(bundle)
    extensions = ecs["agent_receipts"]["verified_extensions"]
    assert extensions["mandate_grant_id"] == signed_mandate["document"]["grant_id"]
    assert extensions["audit_inclusion_present"] is True
    assert extensions["audit_witness_cosignature_count"] == 1
    assert extensions["session_proof_mode"] == "folded"
    assert extensions["recursive_composition_present"] is True
    assert extensions["recursive_verification_key_id"] == "vk-recursive"
    assert extensions["tee_quote_kind"] == "nitro"

    otel = export_siem_otel(bundle)
    assert (
        otel["attributes"]["agent.receipt.extension.mandate_grant_id"]
        == signed_mandate["document"]["grant_id"]
    )
    assert otel["attributes"]["agent.receipt.extension.audit_witness_cosignature_count"] == 1

    cef = export_siem_cef(bundle)
    assert "mandateGrantId=" in cef
    assert "auditWitnessCosignatureCount=1" in cef
