"""Actor identity binding across multi-step flows (ID-1 / F7 / SM-15)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentauth.core.hash_util import hash_canonical_json


@dataclass
class ActorBindingPolicy:
    enabled: bool = False
    require_actor: bool = True
    fail_on_actor_change: bool = True
    allowed_actor_patterns: list[str] = field(default_factory=list)

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> ActorBindingPolicy:
        if not isinstance(raw, dict):
            return cls()
        patterns = raw.get("allowed_actor_patterns") or raw.get("github_actor_patterns")
        return cls(
            enabled=bool(raw.get("enabled", False)),
            require_actor=bool(raw.get("require_actor", True)),
            fail_on_actor_change=bool(raw.get("fail_on_actor_change", True)),
            allowed_actor_patterns=[str(item) for item in (patterns or [])],
        )


def _matches_any(value: str, patterns: list[str]) -> bool:
    import fnmatch

    for pattern in patterns:
        if fnmatch.fnmatchcase(value, pattern):
            return True
    return False


def actor_identity_block(
    *,
    github_actor: str | None = None,
    oidc_subject: str | None = None,
    oidc_issuer: str | None = None,
    spiffe_id: str | None = None,
    workload_principal: str | None = None,
) -> dict[str, Any]:
    """Receipt-facing actor identity (GitHub + optional OIDC/SPIFFE)."""
    block: dict[str, Any] = {
        "schema": "agent-receipts.actor-identity.v1",
        "github_actor": github_actor,
        "oidc_subject": oidc_subject,
        "oidc_issuer": oidc_issuer,
        "spiffe_id": spiffe_id,
        "workload_principal": workload_principal,
    }
    block["commitment"] = hash_canonical_json(
        {k: v for k, v in block.items() if k != "commitment" and v is not None}
    )
    return block


def evaluate_actor_binding(
    *,
    github_actor: str | None,
    authorization: dict[str, Any],
    prior_receipts: list[dict[str, Any]] | None = None,
    policy: ActorBindingPolicy | None = None,
    oidc_subject: str | None = None,
) -> list[dict[str, Any]]:
    """Return structured gate reasons for actor binding violations."""
    cfg = policy or ActorBindingPolicy()
    agent_block = authorization.get("agent") or {}
    patterns = cfg.allowed_actor_patterns or list(
        agent_block.get("github_actor_patterns") or []
    )
    reasons: list[dict[str, Any]] = []

    if cfg.require_actor or patterns:
        if not github_actor and not oidc_subject:
            reasons.append(
                {
                    "code": "agent_identity_missing",
                    "message": "missing actor identity for identity-bound mandate (fail closed)",
                    "evidence": {"authorized_patterns": patterns},
                }
            )
            return reasons

    actor = github_actor or oidc_subject or ""
    if patterns and actor and not _matches_any(actor, patterns):
        reasons.append(
            {
                "code": "agent_identity_mismatch",
                "message": f"PR actor {actor!r} does not match the authorized Devin actor",
                "evidence": {"authorized_patterns": patterns, "actual": actor},
            }
        )

    if cfg.fail_on_actor_change and prior_receipts:
        prior_actors = []
        for receipt in prior_receipts:
            agent = receipt.get("agent") or {}
            identity = receipt.get("actor_identity") or {}
            prior = agent.get("github_actor") or identity.get("github_actor") or identity.get(
                "oidc_subject"
            )
            if prior:
                prior_actors.append(str(prior))
        if prior_actors and actor:
            if prior_actors[-1] != actor:
                reasons.append(
                    {
                        "code": "actor_chain_break",
                        "message": (
                            f"actor changed mid-chain ({prior_actors[-1]!r} -> {actor!r}) "
                            "without explicit authorization"
                        ),
                        "evidence": {
                            "prior_actor": prior_actors[-1],
                            "current_actor": actor,
                        },
                    }
                )
    return reasons
