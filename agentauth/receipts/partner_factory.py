"""Build AgentWrapper from partner config (shared by pilot and integrations)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.receipts.certificate import (
    dev_certificate,
    load_or_create_partner_certificate,
    sign_with_managed_issuer,
)
from agentauth.receipts.partner_config import PartnerConfig
from agentauth.receipts.policy import Policy
from agentauth.receipts.wrapper import AgentWrapper


def build_agent_from_config(
    cfg: PartnerConfig,
    model: Callable[[dict[str, Any]], dict[str, Any]],
) -> AgentWrapper:
    policy = Policy.from_yaml(cfg.policy_path)
    kwargs = cfg.to_agent_kwargs()
    kwargs["policy"] = policy

    cert_path = cfg.effective_certificate_path()
    if cert_path is not None:
        kwargs["certificate"] = load_or_create_partner_certificate(
            cert_path,
            policy_commitment=policy.commitment(),
            model_hash=cfg.model_provenance_hash,
            organization=cfg.organization,
            principal_id=cfg.principal_id,
            scope=["agent.run"],
        )
    else:
        kwargs["certificate"] = sign_with_managed_issuer(
            dev_certificate(
                policy.commitment(),
                model_hash=cfg.model_provenance_hash,
                organization=cfg.organization,
                principal_id=cfg.principal_id,
                scope=["agent.run"],
            )
        )

    return AgentWrapper(model=model, **kwargs)
