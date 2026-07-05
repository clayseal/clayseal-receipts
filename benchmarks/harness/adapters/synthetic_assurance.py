from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Iterator

from agentauth.receipts.proof import AttestationPath

from harness.agent_setup import apply_agent_policy
from harness.pipeline import fraud_policy
from harness.synthetic_common import synthetic_case, synthetic_meta
from harness.synthetic_helpers import (
    allow_stub_proofs,
    export_identity_receipt,
    issue_session,
    nitro_test_root,
    tamper_bundle,
    verify_bundle,
)
from harness.synthetic_scenarios import scenarios_for_suite
from harness.types import BenchmarkCase


def iter_cases(*, limit: int | None = None, options=None) -> Iterator[BenchmarkCase]:  # noqa: ARG001
    dispatch = {
        "assurance_tee_mock_verify_valid": _assurance_tee_mock_verify_valid,
        "assurance_tee_missing_blind_spot": _assurance_tee_missing_blind_spot,
        "assurance_inject_output_hash_mismatch": _assurance_inject_output_hash_mismatch,
        "assurance_inject_identity_jwt_tamper": _assurance_inject_identity_jwt_tamper,
        "assurance_inject_strip_execution_proof": _assurance_inject_strip_execution_proof,
    }
    cases: list[BenchmarkCase] = []
    for spec in scenarios_for_suite("synthetic_assurance"):
        factory = dispatch.get(spec["id"])
        if factory is None:
            continue
        cases.append(factory(spec))
    if limit is not None:
        cases = cases[:limit]
    yield from cases


def _from_spec(spec: dict, execute) -> BenchmarkCase:
    return synthetic_case(
        "synthetic_assurance",
        spec["id"],
        spec["description"],
        spec["category"],
        execute,
        attack_surface=spec["attack_surface"],
        defense_layer=spec["defense_layer"],
        ev=spec.get("ev", "EV-203"),
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


def _assurance_tee_mock_verify_valid(spec: dict) -> BenchmarkCase:
    def execute(agent):
        import base64

        from agentauth.receipts.export import build_receipt_bundle
        from agentauth.receipts.tee import TeeQuote, TeeQuoteFormat

        from harness.nitro_fixture import process_nitro_quote_bytes, process_nitro_root_pem

        client, session = issue_session("assurance-tee", agent_type="tee-test", owner="tee@bench")
        run_result, _bundle = export_identity_receipt(agent, client=client, session=session)
        process_nitro_root_pem()
        document = process_nitro_quote_bytes()
        run_result.proof.attestation_path = AttestationPath.TEE_HYBRID
        run_result.proof.bundle.tee_quote = TeeQuote(
            format=TeeQuoteFormat.NITRO_ENCLAVE_V1,
            quote_b64=base64.standard_b64encode(document).decode("ascii"),
            max_age_seconds=None,
        ).to_dict()
        with allow_stub_proofs():
            bundle = build_receipt_bundle(
                run_result,
                certificate=agent.certificate,
                policy=fraud_policy(),
            )
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
                verify_reasons=list(check.get("reasons") or []),
            ),
        }

    return _from_spec(spec, execute)


def _assurance_tee_missing_blind_spot(spec: dict) -> BenchmarkCase:
    def execute(agent):
        from agentauth.receipts.export import build_receipt_bundle

        apply_agent_policy(agent, fraud_policy())
        agent.model = lambda _inp: {"decision": "approve", "fraud_score": 0.05}
        run_result = agent.run({"transaction_id": "tee-gap", "amount": 10.0})
        run_result.proof.attestation_path = AttestationPath.TEE_HYBRID
        run_result.proof.bundle.tee_quote = None
        bundle = build_receipt_bundle(
            run_result,
            certificate=agent.certificate,
            policy=agent.policy,
        )
        check = verify_bundle(bundle)
        reasons = list(check.get("reasons") or [])
        tee_gap = not check.get("valid") and any("tee" in reason.lower() for reason in reasons)
        observed = "verify_invalid_no_tee" if tee_gap else "verify_unexpected_pass"
        return {
            "ok": observed == "verify_invalid_no_tee",
            "run_result": run_result,
            "require_audit": False,
            "metadata": _meta(
                spec,
                expected="verify_invalid_no_tee",
                observed=observed,
                verify_reasons=reasons,
                documented_gap="TEE_HYBRID without quote fails verify until Tier 3",
            ),
        }

    return _from_spec(spec, execute)


def _assurance_inject_output_hash_mismatch(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client, session = issue_session("assurance-out", agent_type="inj-test", owner="inj@bench")
        run_result, bundle = export_identity_receipt(agent, client=client, session=session)
        output = dict(bundle.get("output") or {})
        output["decision"] = "deny"
        mutated = tamper_bundle(bundle, path="output", value=output)
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


def _assurance_inject_identity_jwt_tamper(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client, session = issue_session("assurance-id", agent_type="inj-test", owner="inj@bench")
        run_result, bundle = export_identity_receipt(agent, client=client, session=session)
        token = (bundle.get("identity") or {}).get("jwt_svid") or ""
        tampered = token[:-1] + ("x" if token[-1:] != "x" else "y")
        mutated = tamper_bundle(bundle, path="identity.jwt_svid", value=tampered)
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


def _assurance_inject_strip_execution_proof(spec: dict) -> BenchmarkCase:
    def execute(agent):
        client, session = issue_session("assurance-strip", agent_type="inj-test", owner="inj@bench")
        run_result, bundle = export_identity_receipt(agent, client=client, session=session)
        mutated = dict(bundle)
        mutated.pop("execution_proof", None)
        try:
            check = verify_bundle(mutated)
            observed = "verify_invalid" if not check.get("valid") else "verify_unexpected_pass"
        except Exception:
            check = {"valid": False, "reasons": ["execution_proof missing"]}
            observed = "verify_invalid"
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
