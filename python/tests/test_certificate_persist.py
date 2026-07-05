from pathlib import Path

from agentauth.receipts.certificate import load_certificate, load_or_create_partner_certificate
from agentauth.receipts.policy import Policy

ROOT = Path(__file__).resolve().parents[2]


def test_certificate_persist_stable_agent_id(tmp_path: Path):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    path = tmp_path / "agent.json"
    c1 = load_or_create_partner_certificate(
        path,
        policy_commitment=policy.commitment(),
        model_hash="sha256:test-model-v1",
        organization="org",
        principal_id="agent-1",
    )
    c2 = load_or_create_partner_certificate(
        path,
        policy_commitment=policy.commitment(),
        model_hash="sha256:test-model-v1",
        organization="org",
        principal_id="agent-1",
    )
    assert c1.agent_id == c2.agent_id
    assert load_certificate(path).agent_id == c1.agent_id
