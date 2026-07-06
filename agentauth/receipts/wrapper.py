from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.decision import (
    ApprovalMetadata,
    ApprovalState,
    BudgetEffect,
    DecisionResult,
    Obligation,
)
from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.mandate import Mandate
from agentauth.core.operations import (
    CapabilityAuthorizer,
    capability_allows,
    operation_for_action,
)
from agentauth.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext
from agentauth.core.task_scope import TaskScope, resolve_task_mandate

from agentauth.receipts.action_monitor import MonitoringSignal, SessionActionMonitor
from agentauth.receipts.approval import infer_approval_state
from agentauth.receipts.audit import AuditChain
from agentauth.receipts.certificate import AgentCertificate, dev_certificate, load_certificate
from agentauth.receipts.policy import Policy
from agentauth.receipts.policy_engine import (
    PolicyEngine,
    ReservationCallback,
    YamlPolicyEngine,
    default_outcome,
    noop_reservation_callback,
    pre_execution_violations,
)
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.receipts.prover import prove_structural_policy

OperatingMode = Literal["shadow", "recommend", "bounded_auto", "prove"]
REQUIRE_PROVER_ENV = "AGENT_RECEIPTS_REQUIRE_PROVER"

PathForCert = str | Path | AgentCertificate | None


@dataclass
class RunResult:
    output: dict[str, Any]
    proof: ExecutionProof
    audit_record: Any | None
    decision: DecisionResult
    execution_context: ExecutionContext

    @property
    def policy_violations(self) -> list[str]:
        return self.decision.violations

    @property
    def decision_outcome(self) -> DecisionOutcome:
        return self.decision.outcome

    @property
    def authority_version(self) -> int:
        return self.decision.authority_version

    @property
    def session_id(self) -> str | None:
        return self.decision.session_id

    @property
    def obligations(self) -> list[Obligation]:
        return self.decision.obligations

    @property
    def recommended_action(self) -> str | None:
        return self.decision.recommended_action

    @property
    def policy_satisfied(self) -> bool:
        return self.decision.policy_satisfied

    @property
    def approval_state(self) -> ApprovalState:
        return self.decision.approval_state

    @property
    def approval_metadata(self) -> ApprovalMetadata | None:
        return self.decision.approval_metadata

    @property
    def budget_effects(self) -> list[BudgetEffect]:
        return self.decision.budget_effects

    def to_legacy_dict(self) -> dict[str, Any]:
        """
        Flat dict matching pre-DecisionResult SDK integrations.

        Prefer ``result.decision`` for new code; this exists for backward compatibility.
        """
        return {
            "output": self.output,
            "policy_violations": list(self.policy_violations),
            "policy_satisfied": self.policy_satisfied,
            "decision_outcome": self.decision_outcome.value,
            "authority_version": self.authority_version,
            "session_id": self.session_id,
            "obligations": [item.to_dict() for item in self.obligations],
            "recommended_action": self.recommended_action,
            "approval_state": self.approval_state.value,
            "approval_metadata": (
                self.approval_metadata.to_dict() if self.approval_metadata else None
            ),
            "budget_effects": [item.to_dict() for item in self.budget_effects],
        }


class AgentWrapper:
    """
    Wrap any callable agent with policy checks, execution proofs, and audit chaining.

    The wrapped `model` must be a callable: `model(input_dict) -> output_dict`.
    Use `ReceiptedMcpGateway` for MCP tool calls (see `agentauth.receipts.mcp`).
    """

    def __init__(
        self,
        model: Callable[[dict[str, Any]], dict[str, Any]],
        policy: Policy,
        *,
        certificate: PathForCert = None,
        certificate_path: str | Path | None = None,
        mode: OperatingMode = "shadow",
        audit_db: str | Path = ".audit/chain.sqlite",
        attestation_path: AttestationPath | None = None,
        prove_policy: bool | None = None,
        prove_inference: bool | None = None,
        prove_composed: bool | None = None,
        prove_recursive: bool = False,
        inference_backend: Literal["ezkl", "risc0", "sp1"] = "ezkl",
        principal_scope: list[str] | None = None,
        model_provenance_hash: str = "sha256:model-dev-v1",
        policy_engine: PolicyEngine | None = None,
        reservation_callback: ReservationCallback | None = None,
        default_authority_binding: AuthorityBinding | dict[str, Any] | None = None,
        session_monitor: SessionActionMonitor | None = None,
        task_mandate: Mandate | dict[str, Any] | None = None,
        capability_authorizer: CapabilityAuthorizer | None = None,
    ) -> None:
        self.model = model
        self.policy = policy
        # Identity bound into every receipt unless a per-run binding overrides it.
        # Set by AgentSession.wrap() from a live attested AgentAuth credential;
        # None means the wrapper runs unbound (the standalone receipts path).
        self.default_authority_binding = default_authority_binding
        self.capability_authorizer = capability_authorizer
        self.policy_engine = policy_engine or YamlPolicyEngine(policy)
        self.reservation_callback = reservation_callback or noop_reservation_callback
        self.mode = mode
        self.audit = AuditChain(audit_db)
        self.prove_policy = prove_policy if prove_policy is not None else mode == "prove"
        self.prove_inference = prove_inference if prove_inference is not None else False
        self.prove_composed = prove_composed if prove_composed is not None else mode == "prove"
        self.prove_recursive = prove_recursive
        self.inference_backend = inference_backend
        self.model_provenance_hash = model_provenance_hash

        cert = certificate
        if cert is None and certificate_path is not None:
            cert = load_certificate(certificate_path)
        if cert is None or isinstance(cert, (str, Path)):
            if mode != "shadow":
                raise ValueError(
                    "non-shadow operating modes require an explicit AgentCertificate "
                    "or certificate_path; dev certificates are only auto-created in shadow mode"
                )
            if isinstance(cert, (str, Path)):
                cert = load_certificate(cert)
            else:
                scope = principal_scope or _default_principal_scope(policy)
                cert = dev_certificate(policy.commitment(), scope=scope)
        elif isinstance(cert, (str, Path)):
            cert = load_certificate(cert)
        self.certificate: AgentCertificate = cert  # type: ignore[assignment]

        if self.certificate.policy_commitment != policy.commitment():
            raise ValueError("certificate policy_commitment does not match Policy")
        if self.model_provenance_hash != self.certificate.model_provenance_hash:
            raise ValueError(
                "model_provenance_hash does not match certificate.model_provenance_hash"
            )

        if attestation_path is not None:
            self.attestation_path = attestation_path
        elif mode == "shadow":
            self.attestation_path = AttestationPath.SHADOW
        elif self.prove_policy:
            self.attestation_path = AttestationPath.FULL_ZK
        else:
            self.attestation_path = AttestationPath.TEE_HYBRID

        self.task_scope: TaskScope | None = None
        self.compiled_resource_scope: list[str] = []
        if task_mandate is not None:
            self.task_scope, self.compiled_resource_scope = resolve_task_mandate(task_mandate)

        if session_monitor is not None:
            self.session_monitor = session_monitor
        elif policy.monitoring.enabled:
            self.session_monitor = SessionActionMonitor(
                monitoring=policy.monitoring,
                canary=policy.canary,
                task_scope=self.task_scope,
            )
        else:
            self.session_monitor = None

    def run(
        self,
        input_data: dict[str, Any],
        *,
        action: str | ActionDescriptor = "agent.run",
        session_id: str | None = None,
        authority_version: int = 1,
        authority_id: str | None = None,
        authority_binding: AuthorityBinding | dict[str, Any] | None = None,
    ) -> RunResult:
        if not self.certificate.is_valid_at():
            raise ValueError("agent certificate is expired or not yet valid")

        execution_context = self._normalize_execution_context(
            action=action,
            context={"input": input_data},
            session_id=session_id,
            authority_version=authority_version,
            authority_id=authority_id,
            authority_binding=authority_binding,
        )
        self._attach_monitoring(execution_context, {"input": input_data}, commit=False)
        pre_violations = pre_execution_violations(
            execution_context,
            self.policy,
            compiled_resource_scope=self.compiled_resource_scope or None,
        )

        if self.mode == "bounded_auto" and pre_violations:
            blocked_output = {
                "status": "blocked",
                "decision": "deny",
                "violations": pre_violations,
            }
            return self.record(
                action=action,
                context={
                    "input": input_data,
                    "authorization": execution_context.authorization or {},
                },
                output=blocked_output,
                extra_violations=pre_violations,
                check_policy_output=False,
                decision_outcome=DecisionOutcome.DENY,
                session_id=session_id,
                authority_version=authority_version,
                authority_id=authority_id,
                authority_binding=authority_binding,
            )

        output = dict(self.model(input_data))
        return self.record(
            action=action,
            context={
                "input": input_data,
                "authorization": execution_context.authorization or {},
            },
            output=output,
            session_id=session_id,
            authority_version=authority_version,
            authority_id=authority_id,
            authority_binding=authority_binding,
        )

    def record(
        self,
        *,
        action: str | ActionDescriptor,
        context: dict[str, Any] | ExecutionContext,
        output: dict[str, Any],
        extra_violations: list[str] | None = None,
        check_policy_output: bool = True,
        session_id: str | None = None,
        authority_version: int = 1,
        authority_id: str | None = None,
        authority_binding: AuthorityBinding | dict[str, Any] | None = None,
        decision_outcome: DecisionOutcome | None = None,
        obligations: list[str | dict[str, Any] | Obligation] | None = None,
        approval_state: ApprovalState | None = None,
        approval_metadata: ApprovalMetadata | None = None,
        reservation_callback: ReservationCallback | None = None,
    ) -> RunResult:
        """
        Build execution proof + audit record for an agent or MCP tool action.

        `context` should include inputs and an `authorization` block for tool calls.
        """
        from agentauth.receipts.proving import policy_check_target, proving_amount_and_score

        if authority_binding is None:
            authority_binding = self.default_authority_binding

        execution_context = self._normalize_execution_context(
            action=action,
            context=context,
            session_id=session_id,
            authority_version=authority_version,
            authority_id=authority_id,
            authority_binding=authority_binding,
        )
        authority_version = execution_context.authority.authority_version
        session_id = execution_context.authority.session_id

        monitoring_signal = self._attach_monitoring(execution_context, context)

        check_target = policy_check_target(output) if check_policy_output else output
        if check_policy_output:
            engine_decision = self.policy_engine.evaluate(
                check_target,
                execution_context=execution_context,
                extra_violations=extra_violations,
            )
            violations = list(engine_decision.violations)
            policy_ok = engine_decision.policy_satisfied
        else:
            violations = list(extra_violations or [])
            policy_ok = len(violations) == 0

        if self.mode == "bounded_auto" and violations:
            if "decision" in output:
                output = {
                    **output,
                    "decision": "abstain",
                    "abstain_reason": "policy_violation",
                }
            elif output.get("status") == "blocked":
                pass
            else:
                output = _blocked_output(output, "policy_violation")
            if check_policy_output:
                engine_decision = self.policy_engine.evaluate(
                    policy_check_target(output),
                    execution_context=execution_context,
                    extra_violations=extra_violations,
                )
                violations = list(engine_decision.violations)
                policy_ok = engine_decision.policy_satisfied

        normalized_obligations = [Obligation.from_value(item) for item in list(obligations or [])]

        reserve = reservation_callback or self.reservation_callback
        reservation = reserve(execution_context, output, violations)
        budget_effects = list(reservation.budget_effects) if reservation else []

        resolved_outcome = decision_outcome
        if (
            reservation is not None
            and reservation.outcome == DecisionOutcome.BUDGET_RESERVATION_REQUIRED
        ):
            resolved_outcome = reservation.outcome
        if resolved_outcome is None:
            resolved_outcome = default_outcome(policy_ok, obligations=normalized_obligations)
            if (
                decision_outcome is None
                and policy_ok
                and monitoring_signal is not None
                and monitoring_signal.review_required
            ):
                resolved_outcome = DecisionOutcome.ALLOW_WITH_REVIEW

        if (
            self.mode == "bounded_auto"
            and policy_ok
            and resolved_outcome
            in {
                DecisionOutcome.ALLOW,
                DecisionOutcome.ALLOW_WITH_OBLIGATIONS,
                DecisionOutcome.ALLOW_WITH_REVIEW,
            }
        ):
            gate = DecisionResult(
                outcome=resolved_outcome,
                policy_satisfied=policy_ok,
                violations=violations,
                obligations=normalized_obligations,
                approval_state=infer_approval_state(resolved_outcome, explicit=approval_state),
                approval_metadata=approval_metadata,
                authority_version=authority_version,
                session_id=session_id,
                budget_effects=budget_effects,
            )
            if not gate.can_execute():
                resolved_outcome = DecisionOutcome.DENY
                if "decision" in output:
                    output = {
                        **output,
                        "decision": "abstain",
                        "abstain_reason": "execution_gate",
                    }
                else:
                    output = _blocked_output(output, "execution_gate")

        proof = ExecutionProof.from_action(
            self.certificate,
            execution_context.to_dict(),
            output,
            policy_satisfied=policy_ok,
            path=self.attestation_path,
            decision_outcome=resolved_outcome,
            authority_version=authority_version,
            session_id=session_id,
            obligations=[item.type for item in normalized_obligations],
        )

        if self.prove_composed and policy_ok:
            from agentauth.receipts.compose import prove_composed as prove_composed_bundle

            amount, score = proving_amount_and_score(context, output)
            composed_bytes = prove_composed_bundle(
                amount=amount,
                fraud_score=score,
                policy_commitment=self.policy.commitment(),
                model_provenance_hash=self.model_provenance_hash,
                output_hash=proof.output_hash,
                context_hash=proof.context_hash,
                policy=self.policy,
                recursive=self.prove_recursive,
                backend=self.inference_backend,
            )
            if composed_bytes is not None:
                proof.bundle.composed_proof = composed_bytes
                proof.bundle.verification_key_id = (
                    "inference_and_policy_recursive_v1"
                    if self.prove_recursive
                    else "inference_and_policy_v1"
                )
            elif self._strict_prover_required():
                raise RuntimeError(
                    "prove_composed was requested, but no composed proof was produced"
                )
        elif self.prove_policy and policy_ok:
            envelope_bytes = prove_structural_policy(
                policy=self.policy,
                output=policy_check_target(output),
                policy_commitment=self.policy.commitment(),
                output_hash=proof.output_hash,
            )
            if envelope_bytes is not None:
                proof.bundle.policy_proof = envelope_bytes
                proof.bundle.verification_key_id = "policy_range_v3"
            elif self._strict_prover_required():
                raise RuntimeError("prove_policy was requested, but no policy proof was produced")

        if self.prove_inference and policy_ok and not proof.bundle.composed_proof:
            from agentauth.receipts.inference import prove_inference as prove_inference_bundle

            amount, _ = proving_amount_and_score(context, output)
            inf_bytes = prove_inference_bundle(
                amount=amount,
                model_provenance_hash=self.model_provenance_hash,
                output_hash=proof.output_hash,
                backend=self.inference_backend,
            )
            if inf_bytes is not None:
                proof.bundle.inference_proof = inf_bytes
            elif self._strict_prover_required():
                raise RuntimeError(
                    "prove_inference was requested, but no inference proof was produced"
                )

        if proof.attestation_path == AttestationPath.FULL_ZK and _proof_bundle_uses_stub(proof):
            if not _env_truthy("AGENT_RECEIPTS_ALLOW_STUB"):
                proof.attestation_path = AttestationPath.SHADOW

        recommended: str | None = None
        if self.mode == "recommend" and violations:
            recommended = "abstain"

        auth_ctx = {
            "mode": self.mode,
            "principal": self.certificate.principal.principal_id,
            "organization": self.certificate.principal.organization,
            "prove_policy": self.prove_policy,
            "decision_outcome": resolved_outcome.value,
            "authority_version": authority_version,
            "session_id": session_id,
            "prior_action_count": execution_context.authority.prior_action_count,
            "obligations": [item.to_dict() for item in normalized_obligations],
            "action": execution_context.action.to_dict(),
            "authority": execution_context.authority.to_dict(),
            **(
                {"authorization": execution_context.authorization}
                if execution_context.authorization is not None
                else {}
            ),
        }
        audit_record = self.audit.append(proof, execution_context.action.action_name, auth_ctx)

        decision = DecisionResult(
            outcome=resolved_outcome,
            policy_satisfied=policy_ok,
            violations=violations,
            obligations=normalized_obligations,
            recommended_action=recommended,
            approval_state=infer_approval_state(resolved_outcome, explicit=approval_state),
            approval_metadata=approval_metadata,
            authority_version=authority_version,
            session_id=session_id,
            budget_effects=budget_effects,
        )

        return RunResult(
            output=output,
            proof=proof,
            audit_record=audit_record,
            decision=decision,
            execution_context=execution_context,
        )

    def _normalize_execution_context(
        self,
        *,
        action: str | ActionDescriptor,
        context: dict[str, Any] | ExecutionContext,
        session_id: str | None,
        authority_version: int,
        authority_id: str | None,
        authority_binding: AuthorityBinding | dict[str, Any] | None,
    ) -> ExecutionContext:
        if isinstance(context, ExecutionContext):
            return context

        action_descriptor = (
            action if isinstance(action, ActionDescriptor) else ActionDescriptor(action_name=action)
        )
        action_raw = context.get("action")
        if isinstance(action_raw, dict):
            action_descriptor = ActionDescriptor.from_dict(action_raw)
        elif isinstance(action_raw, ActionDescriptor):
            action_descriptor = action_raw

        input_data = context.get("input", context)
        if not isinstance(input_data, dict):
            raise TypeError("execution context input must be a dict")

        binding_raw = (
            authority_binding if authority_binding is not None else context.get("authority_binding")
        )
        auth_raw = context.get("authority")
        if isinstance(binding_raw, AuthorityBinding):
            authority = binding_raw.to_authority_context(
                authority_version=authority_version,
                session_id=session_id,
                resource_scope=self.compiled_resource_scope or None,
            )
        elif isinstance(binding_raw, dict):
            authority = AuthorityBinding.from_dict(binding_raw).to_authority_context(
                authority_version=authority_version,
                session_id=session_id,
                resource_scope=self.compiled_resource_scope or None,
            )
        elif isinstance(auth_raw, AuthorityBinding):
            authority = auth_raw.to_authority_context(
                authority_version=authority_version,
                session_id=session_id,
                resource_scope=self.compiled_resource_scope or None,
            )
        elif isinstance(auth_raw, AuthorityContext):
            authority = auth_raw
        elif isinstance(auth_raw, dict):
            authority = AuthorityContext.from_dict(auth_raw)
        else:
            authority = AuthorityContext(
                authority_id=authority_id or str(self.certificate.agent_id),
                authority_version=authority_version,
                session_id=session_id,
                resource_scope=list(self.compiled_resource_scope),
            )

        if self.compiled_resource_scope and not authority.resource_scope:
            authority.resource_scope = list(self.compiled_resource_scope)

        if authority_id:
            authority.authority_id = authority_id
        if session_id is not None:
            authority.session_id = session_id
        if authority_version != 1:
            authority.authority_version = authority_version

        touched_resources = context.get("touched_resources", [])
        if not isinstance(touched_resources, list):
            touched_resources = []
        authorization = context.get("authorization")
        if authorization is not None and not isinstance(authorization, dict):
            raise TypeError("execution context authorization must be a dict when present")
        if self.task_scope is not None:
            authorization = dict(authorization or {})
            authorization.setdefault("task_scope", self.task_scope.to_dict())
        return ExecutionContext(
            action=action_descriptor,
            input=dict(input_data),
            authority=authority,
            authorization=authorization,
            touched_resources=[str(item) for item in touched_resources],
        )

    def _attach_monitoring(
        self,
        execution_context: ExecutionContext,
        context: dict[str, Any] | ExecutionContext,
        *,
        commit: bool = True,
    ):
        if self.session_monitor is None or not self.policy.monitoring.enabled:
            return None
        task_summary: str | None = None
        if isinstance(context, dict):
            task_summary = context.get("task_summary")
            if task_summary is None:
                authorization = context.get("authorization")
                if isinstance(authorization, dict):
                    task_summary = authorization.get("task_summary")
                    raw_scope = authorization.get("task_scope")
                    if task_summary is None and isinstance(raw_scope, dict):
                        task_summary = raw_scope.get("task_summary")
        authorization = execution_context.authorization or {}
        existing = authorization.get("monitoring")
        if isinstance(existing, dict) and commit:
            signal = MonitoringSignal.from_dict(existing)
            self.session_monitor.commit(execution_context)
        elif isinstance(existing, dict) and not commit:
            signal = MonitoringSignal.from_dict(existing)
        else:
            if commit:
                signal = self.session_monitor.observe(
                    execution_context,
                    task_summary=str(task_summary) if task_summary else None,
                )
            else:
                signal = self.session_monitor.evaluate(
                    execution_context,
                    task_summary=str(task_summary) if task_summary else None,
                    commit=False,
                )
        execution_context.authority.prior_action_count = signal.action_index
        authorization = dict(authorization)
        authorization["monitoring"] = signal.to_dict()
        execution_context.authorization = authorization
        return signal

    def _strict_prover_required(self) -> bool:
        if _env_truthy(REQUIRE_PROVER_ENV):
            return True
        return self.mode in {"prove", "bounded_auto"} and (
            self.prove_policy or self.prove_inference or self.prove_composed
        )

    def authorize_action(self, action: ActionDescriptor) -> list[str]:
        """Pre-execution capability check for side-effecting actions."""
        operation = operation_for_action(action)
        if self.capability_authorizer is not None:
            try:
                result = self.capability_authorizer(operation.resource, operation.action)
            except Exception as exc:  # noqa: BLE001 - authorization failure must deny
                return [
                    f"capability token authorization failed for {operation.label()}: {exc}"
                ]
            if result.get("allowed"):
                return []
            reason = str(result.get("reason") or "denied")
            return [f"capability token does not allow {operation.label()}: {reason}"]

        binding = self.default_authority_binding
        if isinstance(binding, AuthorityBinding):
            if (
                binding.evidence_verified
                and binding.has_capability_grant
                and binding.proof_of_possession
                and capability_allows(
                    binding.capability_rules,
                    operation.resource,
                    operation.action,
                )
            ):
                return []

        return [f"capability token is required for {operation.label()}"]


def _default_principal_scope(policy: Policy) -> list[str]:
    scope = ["agent.run"]
    if policy.allowed_tools:
        scope.extend(policy.allowed_tools)
    return scope


def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _blocked_output(output: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "decision": "abstain",
        "abstain_reason": reason,
        "blocked": True,
        "original_output_hash": hash_canonical_json(output),
    }


def _proof_bundle_uses_stub(proof: ExecutionProof) -> bool:
    blobs = [
        blob
        for blob in (
            proof.bundle.inference_proof,
            proof.bundle.composed_proof,
        )
        if blob
    ]
    for blob in blobs:
        try:
            data = json.loads(blob)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        attestation = data.get("attestation")
        if isinstance(attestation, str) and attestation.lower() == "stub":
            return True
        inference = data.get("inference")
        if isinstance(inference, dict):
            nested = inference.get("attestation")
            if isinstance(nested, str) and nested.lower() == "stub":
                return True
    return False
