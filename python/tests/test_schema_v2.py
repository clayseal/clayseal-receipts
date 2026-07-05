"""Receipt bundle schema v2 build, migration, and NDJSON export."""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.export import (
    build_receipt_bundle,
    load_receipts_ndjson,
    verify_receipt_bundle,
    write_receipts_ndjson,
)
from agentauth.receipts.receipt_schema import (
    RECEIPT_BUNDLE_SCHEMA_V1,
    RECEIPT_BUNDLE_SCHEMA_V2,
    migrate_v1_to_v2,
    policy_violations_from_bundle,
)

ROOT = Path(__file__).resolve().parents[2]


def _run_shadow_agent():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0}, session_id="sess-v2")
    return policy, cert, result


def test_build_receipt_bundle_defaults_to_v2():
    policy, cert, result = _run_shadow_agent()
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    assert bundle["schema"] == RECEIPT_BUNDLE_SCHEMA_V2
    for section in ("decision", "authority", "action", "evidence"):
        assert section in bundle
    assert "assurance" not in bundle
    assert "policy_violations" not in bundle
    assert bundle["evidence"]["assurance"]["level"] == "shadow"
    assert bundle["session"]["session_id"] == "sess-v2"


def test_build_receipt_bundle_v1_compat():
    policy, cert, result = _run_shadow_agent()
    bundle = build_receipt_bundle(
        result, certificate=cert, policy=policy, schema_version="v1"
    )
    assert bundle["schema"] == RECEIPT_BUNDLE_SCHEMA_V1
    assert bundle["assurance"]["level"] == "shadow"
    assert "policy_violations" in bundle


def test_migrate_v1_to_v2():
    policy, cert, result = _run_shadow_agent()
    v1 = build_receipt_bundle(
        result, certificate=cert, policy=policy, schema_version="v1"
    )
    v2 = migrate_v1_to_v2(v1)
    assert v2["schema"] == RECEIPT_BUNDLE_SCHEMA_V2
    assert "assurance" not in v2
    assert "policy_violations" not in v2
    assert v2["evidence"]["assurance"]["level"] == "shadow"
    assert policy_violations_from_bundle(v2) == policy_violations_from_bundle(v1)


def test_verify_accepts_v1_and_v2():
    policy, cert, result = _run_shadow_agent()
    v1 = build_receipt_bundle(
        result, certificate=cert, policy=policy, schema_version="v1"
    )
    v2 = build_receipt_bundle(result, certificate=cert, policy=policy)
    for bundle in (v1, v2):
        check = verify_receipt_bundle(bundle)
        assert check["schema"] == bundle["schema"]
        assert check["assurance"]["level"] == "shadow"
        assert "issues" in check


def test_ndjson_roundtrip(tmp_path: Path):
    policy, cert, result = _run_shadow_agent()
    bundles = [
        build_receipt_bundle(result, certificate=cert, policy=policy),
        build_receipt_bundle(
            result, certificate=cert, policy=policy, schema_version="v1"
        ),
    ]
    path = tmp_path / "receipts.ndjson"
    write_receipts_ndjson(path, bundles)
    loaded = load_receipts_ndjson(path)
    assert len(loaded) == 2
    assert loaded[0]["schema"] == RECEIPT_BUNDLE_SCHEMA_V2
    assert loaded[1]["schema"] == RECEIPT_BUNDLE_SCHEMA_V1
