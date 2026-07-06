from __future__ import annotations

from typing import Any, Iterator

from agentauth.receipts import AgentWrapper
from agentauth.core.authority_binding import AuthorityBinding
from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle

from harness.agent_setup import apply_agent_policy
from harness.pipeline import fraud_policy
from harness.synthetic_backend import create_tenant_client, identify_agent
from harness.synthetic_common import synthetic_case, synthetic_meta
from harness.synthetic_helpers import export_identity_receipt, identity_section_for_session, issue_session, verify_bundle
from harness.synthetic_scale import iter_scaled_cases
from harness.synthetic_scenarios import scenarios_for_suite
from harness.types import BenchmarkCase


def iter_cases(*, limit: int | None = None, options=None) -> Iterator[BenchmarkCase]:  # noqa: ARG001
    dispatch = {
        "revoke_baseline_validates": _revoke_baseline_validates,
        "revoke_blocks_validate": _revoke_blocks_validate,
        "revoke_allows_reidentify": _revoke_allows_reidentify,
        "revoke_unknown_agent_404": _revoke_unknown_agent_404,
        "revoke_receipt_bundle_persisted": _revoke_receipt_bundle_persisted,
        "revoke_live_validate_fails": _revoke_live_validate_fails,
        "revoke_offline_bundle_still_valid": _revoke_offline_bundle_still_valid,
        "revoke_identity_bundle_valid_before_revoke": _revoke_identity_bundle_valid_before_revoke,
    }
    cases: list[BenchmarkCase] = []
    for spec in scenarios_for_suite("synthetic_revocation"):
        factory = dispatch.get(spec["id"])
        if factory is None:
            continue
        cases.append(factory(spec))
    cases.extend(iter_scaled_cases("synthetic_revocation"))
    if limit is not None:
        cases = cases[:limit]
    yield from cases


def _from_spec(spec: dict, execute) -> BenchmarkCase:
    return synthetic_case(
        "synthetic_revocation",
        spec["id"],
        spec["description"],
        spec["category"],
        execute,
        attack_surface=spec["attack_surface"],
        defense_layer=spec["defense_layer"],
        ev=spec.get("ev", "EV-103"),
        attack=spec.get("attack"),
    )


def _revoke_baseline_validates(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client, session = issue_session("revoke-baseline", agent_type="revoke-test", owner="bench@revoke")
        try:
            result = session.validate()
            observed = "valid" if result.valid else "invalid"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return _result(spec, observed, expected="valid", ok=observed == "valid", agent_id=session.agent_id)

    return _from_spec(spec, execute)


def _revoke_blocks_validate(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client, session = issue_session("revoke-block", agent_type="revoke-test", owner="bench@revoke")
        session.revoke()
        try:
            session.validate()
            observed = "valid_unexpected"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return _result(
            spec,
            observed,
            expected="error:agent_revoked",
            ok=observed == "error:agent_revoked",
            agent_id=session.agent_id,
        )

    return _from_spec(spec, execute)


def _revoke_allows_reidentify(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client, _ = issue_session("revoke-reid", agent_type="revoke-test", owner="bench@reid")
        first = identify_agent(client, agent_type="revoke-test", owner="bench@reid")
        first.revoke()
        second = identify_agent(client, agent_type="revoke-test", owner="bench@reid")
        try:
            result = second.validate()
            observed = "reidentified_valid" if result.valid else "reidentified_invalid"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        ok = observed == "reidentified_valid" and second.agent_id != first.agent_id
        return _result(
            spec,
            observed,
            expected="reidentified_valid",
            ok=ok,
            first_agent_id=first.agent_id,
            second_agent_id=second.agent_id,
        )

    return _from_spec(spec, execute)


def _revoke_unknown_agent_404(spec: dict) -> BenchmarkCase:
    def execute(_agent):
        from agentauth.identity.errors import AgentAuthError

        client = create_tenant_client("revoke-404")
        try:
            client.revoke("00000000-0000-0000-0000-000000000000")
            observed = "revoked_unexpected"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return _result(
            spec,
            observed,
            expected="error:agent_not_found",
            ok=observed == "error:agent_not_found",
        )

    return _from_spec(spec, execute)


def _revoke_receipt_bundle_persisted(spec: dict) -> BenchmarkCase:
    def execute(agent):
        import base64
        import tempfile
        from pathlib import Path

        from agentauth.receipts import AgentWrapper
        from agentauth.core.authority_binding import AuthorityBinding
        from agentauth.receipts.export import build_receipt_bundle
        from agentauth.receipts.proof import AttestationPath
        from agentauth.receipts.tee import TeeQuote, TeeQuoteFormat

        from harness.nitro_fixture import process_nitro_quote_bytes, process_nitro_root_pem
        from harness.synthetic_helpers import allow_stub_proofs

        client, session = issue_session("revoke-receipt", agent_type="revoke-test", owner="bench@receipt")
        policy = fraud_policy()
        apply_agent_policy(agent, policy)
        binding = AuthorityBinding.from_agentauth_credential(session.credential.to_binding_dict())
        audit_path = Path(tempfile.mkdtemp(prefix="syn-audit-")) / "audit.sqlite"
        wrapper = AgentWrapper(
            lambda _inp: {"decision": "approve", "fraud_score": 0.05},
            policy,
            certificate=agent.certificate,
            default_authority_binding=binding,
            mode="bounded_auto",
            audit_db=str(audit_path),
        )
        run_result = wrapper.run({"transaction_id": "syn-revoke", "amount": 10.0})
        identity = identity_section_for_session(client, session)
        process_nitro_root_pem()
        document = process_nitro_quote_bytes()
        run_result.proof.attestation_path = AttestationPath.TEE_HYBRID
        run_result.proof.bundle.tee_quote = TeeQuote(
            format=TeeQuoteFormat.NITRO_ENCLAVE_V1,
            quote_b64=base64.standard_b64encode(document).decode("ascii"),
            max_age_seconds=None,
        ).to_dict()
        run_result.audit_record = None
        with allow_stub_proofs():
            bundle_before = build_receipt_bundle(
                run_result,
                certificate=wrapper.certificate,
                policy=policy,
                identity=identity,
            )
            session.revoke()
            bundle_after = build_receipt_bundle(
                run_result,
                certificate=wrapper.certificate,
                policy=policy,
                identity=identity,
            )
        gap_open = bool(bundle_before) and bool(bundle_after)
        observed = "receipt_still_exportable" if gap_open else "receipt_missing"
        return {
            "ok": observed == "receipt_still_exportable",
            "run_result": run_result,
            "require_audit": False,
            "metadata": _meta(spec, expected="receipt_still_exportable", observed=observed),
        }

    return _from_spec(spec, execute)


def _revoke_live_validate_fails(spec: dict) -> BenchmarkCase:
    def execute(agent):
        from agentauth.identity.errors import AgentAuthError

        client, session = issue_session("revoke-live", agent_type="revoke-test", owner="bench@live")
        run_result, _bundle = export_identity_receipt(agent, client=client, session=session)
        session.revoke()
        try:
            session.validate()
            observed = "valid_unexpected"
        except AgentAuthError as exc:
            observed = f"error:{exc.code}"
        return {
            "ok": observed == "error:agent_revoked",
            "run_result": run_result,
            "require_audit": False,
            "metadata": _meta(spec, expected="error:agent_revoked", observed=observed),
        }

    return _from_spec(spec, execute)


def _revoke_offline_bundle_still_valid(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client, session = issue_session("revoke-offline", agent_type="revoke-test", owner="bench@offline")
        run_result, bundle = export_identity_receipt(agent, client=client, session=session)
        before = verify_bundle(bundle)
        session.revoke()
        after = verify_bundle(bundle)
        still_valid = bool(after.get("valid"))
        observed = "offline_still_valid" if still_valid else "offline_invalidated"
        return {
            "ok": observed == "offline_still_valid",
            "run_result": run_result,
            "require_audit": False,
            "metadata": _meta(
                spec,
                expected="offline_still_valid",
                observed=observed,
                verify_valid_before=before.get("valid"),
                verify_valid_after=after.get("valid"),
                documented_gap="Offline bundle verify does not consult live revocation state",
            ),
        }

    return _from_spec(spec, execute)


def _revoke_identity_bundle_valid_before_revoke(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client, session = issue_session("revoke-pre", agent_type="revoke-test", owner="bench@pre")
        run_result, bundle = export_identity_receipt(agent, client=client, session=session)
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
                spiffe_id=session.credential.spiffe_id,
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
