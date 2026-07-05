from __future__ import annotations

from typing import Any, Iterator

from harness.synthetic_backend import create_tenant_client, identify_agent
from harness.synthetic_common import synthetic_case, synthetic_meta
from harness.synthetic_helpers import export_identity_receipt, issue_session, tamper_bundle, verify_bundle
from harness.synthetic_scale import iter_scaled_cases
from harness.synthetic_scenarios import scenarios_for_suite
from harness.types import BenchmarkCase


def iter_cases(*, limit: int | None = None, options=None) -> Iterator[BenchmarkCase]:  # noqa: ARG001
    dispatch = {
        "tenant_own_validate_works": _tenant_own_validate_works,
        "tenant_cannot_validate_foreign_token": _tenant_cannot_validate_foreign_token,
        "tenant_cannot_revoke_foreign_agent": _tenant_cannot_revoke_foreign_agent,
        "tenant_spiffe_paths_differ": _tenant_spiffe_paths_differ,
        "tenant_cannot_get_foreign_agent": _tenant_cannot_get_foreign_agent,
        "tenant_cross_validate_token_from_bundle": _tenant_cross_validate_token_from_bundle,
        "tenant_offline_bundle_verify_passes": _tenant_offline_bundle_verify_passes,
        "tenant_cross_tenant_bundle_identity_mismatch": _tenant_cross_tenant_bundle_identity_mismatch,
    }
    cases: list[BenchmarkCase] = []
    for spec in scenarios_for_suite("synthetic_tenant"):
        factory = dispatch.get(spec["id"])
        if factory is None:
            continue
        cases.append(factory(spec))
    cases.extend(iter_scaled_cases("synthetic_tenant"))
    if limit is not None:
        cases = cases[:limit]
    yield from cases


def _from_spec(spec: dict, execute) -> BenchmarkCase:
    return synthetic_case(
        "synthetic_tenant",
        spec["id"],
        spec["description"],
        spec["category"],
        execute,
        attack_surface=spec["attack_surface"],
        defense_layer=spec["defense_layer"],
        ev=spec.get("ev", "EV-102"),
        attack=spec.get("attack"),
    )


def _meta(spec: dict, *, expected: str, observed: str, **extra) -> dict[str, Any]:
    return synthetic_meta(
        category=spec["category"],
        attack=spec.get("attack", "none"),
        attack_surface=spec["attack_surface"],
        defense_layer=spec["defense_layer"],
        expected=expected,
        observed=observed,
        **extra,
    )


def _tenant_own_validate_works(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        _client, session = issue_session("tenant-a-own", agent_type="tenant-test", owner="a@bench")
        try:
            result = session.validate()
            observed = "valid" if result.valid else "invalid"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return _result(spec, observed, expected="valid", ok=observed == "valid")

    return _from_spec(spec, execute)


def _tenant_cannot_validate_foreign_token(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client_a, session_a = issue_session("tenant-a-foreign-val", agent_type="tenant-test", owner="a@bench")
        client_b = create_tenant_client("tenant-b-foreign-val")
        try:
            client_b.validate(session_a.token)
            observed = "valid_unexpected"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return _result(
            spec,
            observed,
            expected="error:invalid_token",
            ok=observed == "error:invalid_token",
            tenant_a_agent=session_a.agent_id,
        )

    return _from_spec(spec, execute)


def _tenant_cannot_revoke_foreign_agent(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client_a, session_a = issue_session("tenant-a-foreign-rev", agent_type="tenant-test", owner="a@bench")
        client_b = create_tenant_client("tenant-b-foreign-rev")
        try:
            client_b.revoke(session_a.agent_id)
            observed = "revoked_unexpected"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return _result(
            spec,
            observed,
            expected="error:agent_not_found",
            ok=observed == "error:agent_not_found",
            tenant_a_agent=session_a.agent_id,
        )

    return _from_spec(spec, execute)


def _tenant_spiffe_paths_differ(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        client_a, session_a = issue_session("tenant-a-spiffe", agent_type="tenant-test", owner="a@bench")
        client_b, session_b = issue_session("tenant-b-spiffe", agent_type="tenant-test", owner="b@bench")
        spiffe_a = session_a.credential.spiffe_id or ""
        spiffe_b = session_b.credential.spiffe_id or ""
        isolated = (
            spiffe_a.startswith("spiffe://")
            and spiffe_b.startswith("spiffe://")
            and spiffe_a != spiffe_b
        )
        observed = "isolated" if isolated else "overlap_or_missing"
        return _result(spec, observed, expected="isolated", ok=isolated, spiffe_a=spiffe_a, spiffe_b=spiffe_b)

    return _from_spec(spec, execute)


def _tenant_cannot_get_foreign_agent(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client_a, session_a = issue_session("tenant-a-foreign-get", agent_type="tenant-test", owner="a@bench")
        client_b = create_tenant_client("tenant-b-foreign-get")
        try:
            client_b.agent(session_a.agent_id)
            observed = "read_unexpected"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return _result(
            spec,
            observed,
            expected="error:agent_not_found",
            ok=observed == "error:agent_not_found",
            tenant_a_agent=session_a.agent_id,
        )

    return _from_spec(spec, execute)


def _tenant_cross_validate_token_from_bundle(spec: dict) -> BenchmarkCase:
    def execute(agent):
        from agentauth.identity.errors import AgentAuthError

        client_a, session_a = issue_session("tenant-a-bundle-val", agent_type="tenant-test", owner="a@bench")
        client_b = create_tenant_client("tenant-b-bundle-val")
        _run_result, bundle = export_identity_receipt(agent, client=client_a, session=session_a)
        token = (bundle.get("identity") or {}).get("jwt_svid")
        try:
            client_b.validate(token)
            observed = "valid_unexpected"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return {
            "ok": observed == "error:invalid_token",
            "run_result": None,
            "require_audit": False,
            "metadata": _meta(spec, expected="error:invalid_token", observed=observed),
        }

    return _from_spec(spec, execute)


def _tenant_offline_bundle_verify_passes(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client_a, session_a = issue_session("tenant-a-offline", agent_type="tenant-test", owner="a@bench")
        run_result, bundle = export_identity_receipt(agent, client=client_a, session=session_a)
        check = verify_bundle(bundle)
        observed = "verify_valid" if check.get("valid") else "verify_invalid"
        return {
            "ok": observed == "verify_valid",
            "run_result": run_result,
            "require_audit": False,
            "metadata": _meta(
                spec,
                expected="verify_valid",
                observed=observed,
                spiffe_id=session_a.credential.spiffe_id,
            ),
        }

    return _from_spec(spec, execute)


def _tenant_cross_tenant_bundle_identity_mismatch(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client_a, session_a = issue_session("tenant-a-jwks", agent_type="tenant-test", owner="a@bench")
        client_b = create_tenant_client("tenant-b-jwks")
        run_result, bundle = export_identity_receipt(agent, client=client_a, session=session_a)
        foreign_jwks = client_b._http.get("/v1/jwks.json")
        mutated = tamper_bundle(bundle, path="identity.issuer_jwks", value=foreign_jwks)
        check = verify_bundle(mutated)
        observed = "verify_invalid" if not check.get("valid") else "verify_unexpected_pass"
        return {
            "ok": observed == "verify_invalid",
            "run_result": run_result,
            "require_audit": False,
            "metadata": _meta(
                spec,
                expected="verify_invalid",
                observed=observed,
                verify_reasons=list(check.get("reasons") or []),
            ),
        }

    return _from_spec(spec, execute)


def _result(spec: dict, observed: str, *, expected: str, ok: bool, **extra) -> dict[str, Any]:
    return {
        "ok": ok,
        "run_result": None,
        "require_audit": False,
        "metadata": _meta(spec, expected=expected, observed=observed, **extra),
    }
