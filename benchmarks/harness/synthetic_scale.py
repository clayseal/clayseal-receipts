from __future__ import annotations

from typing import Iterator

from harness.synthetic_backend import create_tenant_client, identify_agent
from harness.synthetic_common import synthetic_case, synthetic_meta
from harness.types import BenchmarkCase

REVOKE_BLOCK_SCALE = 35
REIDENTIFY_SCALE = 30
TENANT_CROSS_SCALE = 35


def scaled_revocation_cases() -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    cases.extend(_revoke_block_scale(i) for i in range(REVOKE_BLOCK_SCALE))
    cases.extend(_reidentify_scale(i) for i in range(REIDENTIFY_SCALE))
    return cases


def scaled_tenant_cases() -> list[BenchmarkCase]:
    return [_tenant_cross_validate_scale(i) for i in range(TENANT_CROSS_SCALE)]


def _revoke_block_scale(variant: int) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client = create_tenant_client(f"revoke-scale-{variant}")
        session = identify_agent(
            client,
            agent_type=f"revoke-scale-{variant % 7}",
            owner=f"bench-revoke-{variant}@scale.test",
        )
        session.revoke()
        try:
            session.validate()
            observed = "valid_unexpected"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return {
            "ok": observed == "error:agent_revoked",
            "run_result": None,
            "require_audit": False,
            "metadata": synthetic_meta(
                category="control",
                attack="use_revoked_token",
                attack_surface="credential_lifecycle",
                defense_layer="L1_identity",
                expected="error:agent_revoked",
                observed=observed,
                variant=variant,
                scaled=True,
            ),
        }

    return synthetic_case(
        "synthetic_revocation",
        f"revoke_block_scale_{variant:03d}",
        f"Scaled revoke block variant {variant}",
        "control",
        execute,
        attack_surface="credential_lifecycle",
        defense_layer="L1_identity",
        ev="EV-103",
        attack="use_revoked_token",
        scaled=True,
        variant=variant,
    )


def _reidentify_scale(variant: int) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client = create_tenant_client(f"reid-scale-{variant}")
        first = identify_agent(
            client,
            agent_type=f"reid-scale-{variant % 5}",
            owner=f"bench-reid-{variant}@scale.test",
        )
        first.revoke()
        second = identify_agent(
            client,
            agent_type=f"reid-scale-{variant % 5}",
            owner=f"bench-reid-{variant}@scale.test",
        )
        try:
            result = second.validate()
            observed = "reidentified_valid" if result.valid else "reidentified_invalid"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return {
            "ok": observed == "reidentified_valid" and second.agent_id != first.agent_id,
            "run_result": None,
            "require_audit": False,
            "metadata": synthetic_meta(
                category="baseline",
                attack="none",
                attack_surface="credential_lifecycle",
                defense_layer="L1_identity",
                expected="reidentified_valid",
                observed=observed,
                variant=variant,
                scaled=True,
            ),
        }

    return synthetic_case(
        "synthetic_revocation",
        f"revoke_reidentify_scale_{variant:03d}",
        f"Scaled re-identify after revoke variant {variant}",
        "baseline",
        execute,
        attack_surface="credential_lifecycle",
        defense_layer="L1_identity",
        ev="EV-103",
        attack="none",
        scaled=True,
        variant=variant,
    )


def _tenant_cross_validate_scale(variant: int) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client_a = create_tenant_client(f"tenant-a-scale-{variant}")
        client_b = create_tenant_client(f"tenant-b-scale-{variant}")
        session_a = identify_agent(
            client_a,
            agent_type=f"tenant-scale-{variant % 6}",
            owner=f"a-{variant}@scale.test",
        )
        try:
            client_b.validate(session_a.token)
            observed = "valid_unexpected"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return {
            "ok": observed == "error:invalid_token",
            "run_result": None,
            "require_audit": False,
            "metadata": synthetic_meta(
                category="control",
                attack="cross_tenant_validate",
                attack_surface="tenant_boundary",
                defense_layer="L1_identity",
                expected="error:invalid_token",
                observed=observed,
                variant=variant,
                scaled=True,
            ),
        }

    return synthetic_case(
        "synthetic_tenant",
        f"tenant_cross_validate_scale_{variant:03d}",
        f"Scaled cross-tenant validate variant {variant}",
        "control",
        execute,
        attack_surface="tenant_boundary",
        defense_layer="L1_identity",
        ev="EV-102",
        attack="cross_tenant_validate",
        scaled=True,
        variant=variant,
    )


def iter_scaled_cases(suite: str) -> Iterator[BenchmarkCase]:
    if suite == "synthetic_revocation":
        yield from scaled_revocation_cases()
    elif suite == "synthetic_tenant":
        yield from scaled_tenant_cases()
