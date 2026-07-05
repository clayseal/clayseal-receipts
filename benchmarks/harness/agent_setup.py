from __future__ import annotations

from typing import Any

from agentauth.receipts import AgentWrapper
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.policy import Policy
from agentauth.receipts.policy_engine import YamlPolicyEngine


def apply_agent_policy(
    agent: AgentWrapper,
    policy: Policy,
    *,
    scope: list[str] | None = None,
) -> None:
    """Bind a fresh certificate + policy engine (benchmark cases often swap policy)."""
    agent.policy = policy
    agent.policy_engine = YamlPolicyEngine(policy)
    certificate = dev_certificate(policy.commitment())
    certificate.principal.scope = list(scope or [])
    agent.certificate = certificate


def fresh_certificate_for_policy(
    policy: Policy,
    *,
    model_hash: str = "sha256:model-dev-v1",
    scope: list[str] | None = None,
) -> Any:
    certificate = dev_certificate(policy.commitment(), model_hash=model_hash)
    certificate.principal.scope = list(scope or [])
    return certificate
