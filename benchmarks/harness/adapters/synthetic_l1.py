from __future__ import annotations

from typing import Any, Iterator

from harness.synthetic_backend import create_tenant_client
from harness.synthetic_common import synthetic_case, synthetic_meta
from harness.synthetic_helpers import export_identity_receipt, issue_session, tamper_bundle, verify_bundle
from harness.synthetic_scenarios import scenarios_for_suite
from harness.types import BenchmarkCase


def iter_cases(*, limit: int | None = None, options=None) -> Iterator[BenchmarkCase]:  # noqa: ARG001
    dispatch = {
        "l1_jwt_eddsa_valid": _l1_jwt_eddsa_valid,
        "l1_jwt_tampered_invalid": _l1_jwt_tampered_invalid,
        "l1_biscuit_minted": _l1_biscuit_minted,
        "l1_pop_bearer_rejected": _l1_pop_bearer_rejected,
        "l1_key_rotate_old_token_still_valid": _l1_key_rotate_old_token_still_valid,
        "l1_authority_matches_jwt_sub": _l1_authority_matches_jwt_sub,
        "l1_wrong_jwks_invalid": _l1_wrong_jwks_invalid,
    }
    cases: list[BenchmarkCase] = []
    for spec in scenarios_for_suite("synthetic_l1"):
        factory = dispatch.get(spec["id"])
        if factory is None:
            continue
        cases.append(factory(spec))
    if limit is not None:
        cases = cases[:limit]
    yield from cases


def _from_spec(spec: dict, execute) -> BenchmarkCase:
    return synthetic_case(
        "synthetic_l1",
        spec["id"],
        spec["description"],
        spec["category"],
        execute,
        attack_surface=spec["attack_surface"],
        defense_layer=spec["defense_layer"],
        ev=spec.get("ev", "EV-101"),
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


def _l1_jwt_eddsa_valid(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client, session = issue_session("l1-jwt-valid", agent_type="l1-test", owner="l1@bench")
        run_result, bundle = export_identity_receipt(agent, client=client, session=session)
        check = verify_bundle(bundle)
        identity = bundle.get("identity") or {}
        has_jwt = bool(identity.get("jwt_svid")) and bool(identity.get("issuer_jwks"))
        observed = "verify_valid" if check.get("valid") and has_jwt else "verify_invalid"
        return {
            "ok": observed == "verify_valid",
            "run_result": run_result,
            "require_audit": False,
            "metadata": _meta(spec, expected="verify_valid", observed=observed),
        }

    return _from_spec(spec, execute)


def _l1_jwt_tampered_invalid(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client, session = issue_session("l1-jwt-tamper", agent_type="l1-test", owner="l1@bench")
        run_result, bundle = export_identity_receipt(agent, client=client, session=session)
        token = (bundle.get("identity") or {}).get("jwt_svid") or ""
        tampered_token = token[:-1] + ("a" if token[-1:] != "a" else "b")
        mutated = tamper_bundle(bundle, path="identity.jwt_svid", value=tampered_token)
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


def _l1_biscuit_minted(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        client = create_tenant_client("l1-biscuit")
        session = client.identify(
            agent_type="l1-test",
            owner="l1@bench",
            capabilities=[{"resource": "transactions", "action": "score"}],
            ttl_seconds=3600,
        )
        observed = "biscuit_present" if session.biscuit else "biscuit_missing"
        return {
            "ok": observed == "biscuit_present",
            "run_result": None,
            "require_audit": False,
            "metadata": _meta(spec, expected="biscuit_present", observed=observed),
        }

    return _from_spec(spec, execute)


def _l1_pop_bearer_rejected(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client, session = issue_session("l1-pop", agent_type="l1-test", owner="l1@bench")
        try:
            client.validate(session.token)
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


def _l1_key_rotate_old_token_still_valid(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        client, session = issue_session("l1-rotate", agent_type="l1-test", owner="l1@bench")
        client._http.post("/v1/keys/rotate")
        try:
            result = session.validate()
            observed = "old_token_still_valid" if result.valid else "old_token_invalid"
        except Exception:
            observed = "old_token_invalid"
        return {
            "ok": observed == "old_token_still_valid",
            "run_result": None,
            "require_audit": False,
            "metadata": _meta(
                spec,
                expected="old_token_still_valid",
                observed=observed,
                documented_gap="Retired JWT signing keys remain in JWKS until token expiry",
            ),
        }

    return _from_spec(spec, execute)


def _l1_authority_matches_jwt_sub(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client, session = issue_session("l1-authority", agent_type="l1-test", owner="l1@bench")
        run_result, bundle = export_identity_receipt(agent, client=client, session=session)
        authority = bundle.get("authority") or {}
        identity = bundle.get("identity") or {}
        sub = identity.get("spiffe_id")
        principal = authority.get("workload_principal")
        matched = sub is not None and principal == sub
        observed = "authority_matches_sub" if matched else "authority_mismatch"
        return {
            "ok": observed == "authority_matches_sub",
            "run_result": run_result,
            "require_audit": False,
            "metadata": _meta(
                spec,
                expected="authority_matches_sub",
                observed=observed,
                spiffe_id=sub,
                workload_principal=principal,
            ),
        }

    return _from_spec(spec, execute)


def _l1_wrong_jwks_invalid(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client_a, session_a = issue_session("l1-jwks-a", agent_type="l1-test", owner="a@bench")
        client_b = create_tenant_client("l1-jwks-b")
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
