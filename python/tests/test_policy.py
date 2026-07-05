from pathlib import Path

from agentauth.receipts import Policy

ROOT = Path(__file__).resolve().parents[2]


def test_policy_from_yaml_and_check():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    assert policy.commitment()
    ok = {"decision": "approve", "fraud_score": 0.1}
    assert policy.check_output(ok) == []
    bad = {"decision": "approve", "fraud_score": 1.5}
    assert any("fraud_score" in v for v in policy.check_output(bad))
