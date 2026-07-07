from __future__ import annotations

import json
import os
import tempfile
import time
import traceback
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from agentauth.receipts import AgentWrapper, Policy
from agentauth.core.signing import SigningKey, sign_bundle
from agentauth.receipts.certificate import (
    AgentCertificate,
    certificate_ref_hash,
    sign_certificate,
)
from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle
from agentauth.receipts.inference import InferenceBackend
from agentauth.receipts.mcp import ToolCallResult
from agentauth.receipts.tamper import analyze_bundle_tampering
from agentauth.receipts.wrapper import RunResult
from harness.identity_metrics import bundle_identity_flags
from harness.prove_metrics import proof_byte_counts
from harness.agent_setup import fresh_certificate_for_policy
from harness.paths import REPO_POLICIES
from harness.types import BenchmarkCase, CaseResult

OperatingMode = Literal["shadow", "recommend", "bounded_auto", "prove"]
DEFAULT_PROVE_MODEL_HASH = "sha256:fraud-head-onnx-v1"


@dataclass
class PipelineConfig:
    mode: OperatingMode = "bounded_auto"
    export_receipts: bool = True
    results_dir: Path | None = None
    with_identity: bool = False
    require_verify: bool = False
    tamper_analysis: bool = False
    shared_audit_db: bool = False
    inference_backend: InferenceBackend = "ezkl"
    model_provenance_hash: str = DEFAULT_PROVE_MODEL_HASH
    prove_composed: bool | None = None
    attach_mock_tee: bool = False


class BenchmarkPipeline:
    """Run one benchmark case through AgentWrapper -> export -> verify -> audit."""

    def __init__(self, policy: Policy, *, config: PipelineConfig | None = None) -> None:
        self.config = config or PipelineConfig()
        self.policy = policy
        self.certificate = fresh_certificate_for_policy(policy)
        self._tmpdir = tempfile.mkdtemp(prefix="agent-receipts-bench-")
        self._audit_path = str(Path(self._tmpdir) / "audit.sqlite")
        self._identity: dict[str, Any] | None = None
        self._audit_signing_key = None
        self._bundle_signing_key: SigningKey | None = None
        self._certificate_issuer_key: SigningKey | None = None
        self._strict_export_signing = (
            self.config.require_verify
            or self.config.attach_mock_tee
            or self.config.mode == "prove"
        )
        if self.config.export_receipts:
            from agentauth.core.signing import generate_keypair

            self._audit_signing_key = generate_keypair()
            if self._strict_export_signing:
                self._bundle_signing_key = generate_keypair()
                self._certificate_issuer_key = generate_keypair()
        if self.config.with_identity:
            self._identity = self._bootstrap_identity()

    def _fresh_audit_path(self, case_id: str) -> str:
        safe = case_id.replace("/", "_").replace("\\", "_")[:64]
        return str(Path(self._tmpdir) / f"audit_{safe}_{uuid.uuid4().hex[:8]}.sqlite")

    def _bootstrap_identity(self) -> dict[str, Any]:
        from harness.bootstrap import identify_dev_agent

        return identify_dev_agent()

    def new_agent(self, model: Any, *, case_id: str = "case") -> AgentWrapper:
        model_hash = (
            self.config.model_provenance_hash
            if self.config.mode == "prove"
            else "sha256:model-dev-v1"
        )
        certificate = fresh_certificate_for_policy(
            self.policy,
            model_hash=model_hash,
        )
        certificate = self._sign_certificate_for_export(certificate)
        audit_path = (
            self._audit_path
            if self.config.shared_audit_db
            else self._fresh_audit_path(case_id)
        )
        kwargs: dict[str, Any] = {
            "model": model,
            "policy": self.policy,
            "certificate": certificate,
            "mode": self.config.mode,
            "audit_db": audit_path,
            "model_provenance_hash": model_hash,
            "inference_backend": self.config.inference_backend,
        }
        if self.config.prove_composed is not None:
            kwargs["prove_composed"] = self.config.prove_composed
        if self._identity:
            kwargs["default_authority_binding"] = self._identity["authority_binding"]
        agent = AgentWrapper(**kwargs)
        if self._audit_signing_key is not None:
            agent.audit.signing_key = self._audit_signing_key
        return agent

    def _sign_certificate_for_export(self, certificate: AgentCertificate) -> AgentCertificate:
        if self._certificate_issuer_key is None or certificate.issuer_signature is not None:
            return certificate
        return sign_certificate(certificate, self._certificate_issuer_key)

    def _prepare_certificate_for_export(
        self,
        run_result: RunResult,
        agent: AgentWrapper,
    ) -> AgentCertificate:
        certificate = self._sign_certificate_for_export(agent.certificate)
        agent.certificate = certificate
        expected_ref = certificate_ref_hash(certificate)
        if run_result.proof.certificate_ref != expected_ref:
            run_result.proof.certificate_ref = expected_ref
            if run_result.audit_record is not None:
                # The proof hash feeds the audit record; changing certificate_ref after
                # execution would otherwise leave a stale inclusion claim.
                run_result.audit_record = None
        return certificate

    @contextmanager
    def _strict_verification_trust_env(self):
        keys: dict[str, str] = {}
        if self._bundle_signing_key is not None:
            keys["AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS"] = (
                self._bundle_signing_key.public_key_hex
            )
        if self._certificate_issuer_key is not None:
            keys["AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS"] = (
                self._certificate_issuer_key.public_key_hex
            )
        previous = {key: os.environ.get(key) for key in keys}
        os.environ.update(keys)
        try:
            yield
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    @staticmethod
    def _attach_mock_tee(run_result: RunResult, agent: AgentWrapper) -> None:
        import base64

        from agentauth.receipts.audit import execution_proof_hash
        from agentauth.core.hash_util import hash_canonical_json
        from agentauth.receipts.proof import AttestationPath
        from agentauth.receipts.tee import TeeQuote, TeeQuoteFormat

        from harness.nitro_fixture import process_nitro_quote_bytes, process_nitro_root_pem

        process_nitro_root_pem()
        document = process_nitro_quote_bytes()
        run_result.proof.attestation_path = AttestationPath.TEE_HYBRID
        run_result.proof.bundle.tee_quote = TeeQuote(
            format=TeeQuoteFormat.NITRO_ENCLAVE_V1,
            quote_b64=base64.standard_b64encode(document).decode("ascii"),
            max_age_seconds=None,
        ).to_dict()

        record = run_result.audit_record
        if record is not None:
            new_hash = execution_proof_hash(run_result.proof)
            created_at = (
                record.created_at.isoformat()
                if hasattr(record.created_at, "isoformat")
                else str(record.created_at)
            )
            body = {
                "proof_id": str(run_result.proof.proof_id),
                "execution_proof_hash": new_hash,
                "action": record.action,
                "authorization_context": record.authorization_context,
                "created_at": created_at,
                "prev_hash": record.prev_hash,
            }
            new_record_hash = hash_canonical_json(body)
            record.execution_proof_hash = new_hash
            record.record_hash = new_record_hash
            if agent.audit.signing_key is not None:
                record.signature = agent.audit.signing_key.sign(
                    {"record_hash": new_record_hash}
                )

    def run_case(self, case: BenchmarkCase) -> CaseResult:
        started = time.perf_counter()
        if case.execute is None:
            return CaseResult(
                suite=case.suite,
                case_id=case.case_id,
                ok=False,
                latency_ms=0.0,
                error="case has no execute callable",
                metadata=dict(case.metadata),
            )

        model = case.model or (lambda _inp: {"decision": "approve", "fraud_score": 0.0})
        agent = self.new_agent(model, case_id=case.case_id)
        try:
            outcome = case.execute(agent)
            latency_ms = (time.perf_counter() - started) * 1000.0
            return self._finalize_case(case, agent, outcome, latency_ms)
        except Exception as exc:  # noqa: BLE001
            latency_ms = (time.perf_counter() - started) * 1000.0
            return CaseResult(
                suite=case.suite,
                case_id=case.case_id,
                ok=False,
                latency_ms=latency_ms,
                error=f"{type(exc).__name__}: {exc}",
                metadata={**case.metadata, "traceback": traceback.format_exc()},
            )

    @staticmethod
    def _coerce_run_result(value: Any) -> RunResult | None:
        if value is None:
            return None
        if isinstance(value, RunResult):
            return value
        if isinstance(value, ToolCallResult):
            return RunResult(
                output=value.output,
                proof=value.proof,
                audit_record=value.audit_record,
                decision=value.decision,
                execution_context=value.execution_context,
            )
        raise TypeError(f"unsupported run_result type: {type(value)!r}")

    def _finalize_case(
        self,
        case: BenchmarkCase,
        agent: AgentWrapper,
        outcome: dict[str, Any],
        latency_ms: float,
    ) -> CaseResult:
        run_result = self._coerce_run_result(outcome.get("run_result"))
        policy_satisfied = outcome.get("policy_satisfied")
        decision_outcome = outcome.get("decision_outcome")
        if run_result is not None:
            policy_satisfied = run_result.policy_satisfied
            decision_outcome = run_result.decision_outcome.value

        export_ok = False
        verify_valid: bool | None = None
        verify_reasons: list[str] = []
        tamper_total_mutations: int | None = None
        tamper_detected_mutations: int | None = None
        tamper_invalidated_mutations: int | None = None
        tamper_detection_rate: float | None = None
        tamper_invalidation_rate: float | None = None
        tamper_survivor_paths: list[str] = []
        extra_metadata = dict(case.metadata)
        if self.config.with_identity:
            extra_metadata["with_identity"] = True
        if self.config.export_receipts and run_result is not None:
            if self.config.attach_mock_tee:
                self._attach_mock_tee(run_result, agent)
            certificate = self._prepare_certificate_for_export(run_result, agent)
            identity = outcome.get("identity") or outcome.get("identity_section")
            if identity is None and self._identity:
                identity = self._identity.get("identity_section")
            bundle = build_receipt_bundle(
                run_result,
                certificate=certificate,
                policy=self.policy,
                policy_path=REPO_POLICIES / "fraud_decision.yaml"
                if self.policy.name == "fraud_decision"
                else None,
                context=outcome.get("export_context"),
                identity=identity,
                audit_chain=agent.audit,
            )
            if self._bundle_signing_key is not None:
                sign_bundle(bundle, self._bundle_signing_key, role="benchmark-harness")
            if self.config.results_dir:
                receipt_path = self.config.results_dir / f"{case.suite}_{case.case_id}.json"
                receipt_path.parent.mkdir(parents=True, exist_ok=True)
                receipt_path.write_text(json.dumps(bundle, indent=2))
                extra_metadata["receipt_path"] = str(receipt_path)
            export_ok = True
            with self._strict_verification_trust_env():
                check = verify_receipt_bundle(bundle)
            verify_valid = bool(check.get("valid"))
            verify_reasons = list(check.get("reasons") or [])
            if self.config.with_identity:
                extra_metadata.update(bundle_identity_flags(bundle))
                if self._identity and self._identity.get("session"):
                    try:
                        live = self._identity["session"].validate()
                        extra_metadata["live_validate_ok"] = bool(live.valid)
                    except Exception as exc:  # noqa: BLE001
                        extra_metadata["live_validate_ok"] = False
                        extra_metadata["live_validate_error"] = type(exc).__name__
            if self.config.tamper_analysis:
                tamper = analyze_bundle_tampering(bundle)
                tamper_total_mutations = tamper.total_mutations
                tamper_detected_mutations = tamper.detected_mutations
                tamper_invalidated_mutations = tamper.invalidated_mutations
                tamper_detection_rate = tamper.detection_rate
                tamper_invalidation_rate = tamper.invalidation_rate
                tamper_survivor_paths = [
                    item.path or item.mutation_id
                    for item in tamper.survivors
                ]
                if self.config.results_dir:
                    tamper_path = (
                        self.config.results_dir
                        / f"{case.suite}_{case.case_id}.tamper.json"
                    )
                    tamper_path.write_text(json.dumps(tamper.to_dict(), indent=2))
                    extra_metadata["tamper_report_path"] = str(tamper_path)

        if self.config.mode == "prove" and run_result is not None:
            extra_metadata.update(proof_byte_counts(run_result))
            extra_metadata["inference_backend"] = self.config.inference_backend
            extra_metadata["prove_composed"] = (
                self.config.prove_composed
                if self.config.prove_composed is not None
                else True
            )

        audit_chain_ok = False
        audit_records = len(agent.audit)
        try:
            agent.audit.verify_chain()
            audit_chain_ok = True
        except Exception:  # noqa: BLE001
            audit_chain_ok = False

        ok = bool(outcome.get("ok", True))
        if ok and outcome.get("require_policy_ok", False) and policy_satisfied is False:
            ok = False
        if ok and outcome.get("require_verify", False) and verify_valid is not True:
            ok = False
        if ok and self.config.require_verify and verify_valid is not True:
            ok = False
        if ok and outcome.get("require_audit", True) and not audit_chain_ok:
            ok = False

        return CaseResult(
            suite=case.suite,
            case_id=case.case_id,
            ok=ok,
            latency_ms=latency_ms,
            policy_satisfied=policy_satisfied,
            decision_outcome=decision_outcome,
            export_ok=export_ok,
            verify_valid=verify_valid,
            verify_reasons=verify_reasons,
            audit_records=audit_records,
            audit_chain_ok=audit_chain_ok,
            tamper_total_mutations=tamper_total_mutations,
            tamper_detected_mutations=tamper_detected_mutations,
            tamper_invalidated_mutations=tamper_invalidated_mutations,
            tamper_detection_rate=tamper_detection_rate,
            tamper_invalidation_rate=tamper_invalidation_rate,
            tamper_survivor_paths=tamper_survivor_paths,
            error=outcome.get("error"),
            metadata={**extra_metadata, **(outcome.get("metadata") or {})},
        )


def fraud_policy() -> Policy:
    return Policy.from_yaml(REPO_POLICIES / "fraud_decision.yaml")


def mcp_policy() -> Policy:
    from harness.paths import POLICIES

    return Policy.from_yaml(POLICIES / "mcp_permissive.yaml")


def tau2_policy() -> Policy:
    from harness.paths import POLICIES

    return Policy.from_yaml(POLICIES / "tau2_mock.yaml")


def bfcl_policy(allowed_tool: str) -> Policy:
    return Policy.from_dict(
        {
            "version": 1,
            "name": f"bfcl_{allowed_tool}",
            "tier": "tool_trace",
            "capability": "operator_attested",
            "allowed_tools": {"tools": [allowed_tool]},
            "output_schema": {"fields": ["status", "tool"], "required": []},
        }
    )
