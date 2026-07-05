"""Policy-engine abstraction returning DecisionResult (L3-15, L3-8)."""

from __future__ import annotations

import fnmatch
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from agentauth.receipts.action_monitor import MonitoringSignal
from agentauth.core.decision import BudgetEffect, DecisionResult, Obligation
from agentauth.receipts.policy import Policy
from agentauth.receipts.proof import DecisionOutcome
from agentauth.core.resource_refs import parse_resource_ref
from agentauth.capabilities.task_scope import (
    TaskScope,
    action_path_candidates,
    path_matches_any,
)
from agentauth.core.runtime import (
    ActionDescriptor,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)


@runtime_checkable
class PolicyEngine(Protocol):
    """Evaluate an action output and return lower-layer decision semantics."""

    def evaluate(
        self,
        output: dict[str, Any],
        *,
        execution_context: ExecutionContext | None = None,
        extra_violations: list[str] | None = None,
    ) -> DecisionResult: ...


class YamlPolicyEngine:
    """Default adapter over committed YAML `Policy` rules."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate(
        self,
        output: dict[str, Any],
        *,
        execution_context: ExecutionContext | None = None,
        extra_violations: list[str] | None = None,
    ) -> DecisionResult:
        violations = list(extra_violations or [])
        if execution_context is not None:
            violations.extend(_authority_violations(execution_context, self.policy))
            violations.extend(_task_scope_violations(execution_context))
            violations.extend(_monitoring_violations(execution_context, self.policy))
        violations.extend(self.policy.check_output(output))
        policy_ok = len(violations) == 0
        authority_version = 1
        session_id = None
        if execution_context is not None:
            authority_version = execution_context.authority.authority_version
            session_id = execution_context.authority.session_id
        outcome = default_outcome(policy_ok, obligations=[])
        return DecisionResult(
            outcome=outcome,
            policy_satisfied=policy_ok,
            violations=violations,
            authority_version=authority_version,
            session_id=session_id,
        )


def default_outcome(
    policy_ok: bool,
    *,
    obligations: list[Obligation],
) -> DecisionOutcome:
    if not policy_ok:
        return DecisionOutcome.DENY
    if obligations:
        return DecisionOutcome.ALLOW_WITH_OBLIGATIONS
    return DecisionOutcome.ALLOW


def _parse_timestamp(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _authority_violations(
    execution_context: ExecutionContext, policy: Policy | None = None
) -> list[str]:
    authority = execution_context.authority
    violations: list[str] = []

    if authority.lease_query_id:
        if not execution_context.query_id:
            violations.append(
                "authority lease_query_id requires a matching execution_context.query_id"
            )
        elif execution_context.query_id != authority.lease_query_id:
            violations.append("execution_context.query_id does not match authority lease_query_id")

    if authority.lease_remaining_calls is not None and authority.lease_remaining_calls <= 0:
        violations.append("authority lease_remaining_calls exhausted")

    if policy is not None and policy.min_trust_tier:
        from agentauth.receipts.assurance import meets_assurance_threshold

        effective_tier, trust_issues = _effective_authority_trust_tier(authority)
        violations.extend(trust_issues)
        if not effective_tier:
            violations.append(
                f"authority missing trust_tier required by policy ({policy.min_trust_tier})"
            )
        elif not meets_assurance_threshold(effective_tier, policy.min_trust_tier):
            violations.append(
                f"authority effective trust_tier {effective_tier!r} is below policy minimum "
                f"{policy.min_trust_tier!r}"
            )

    if authority.expires_at:
        try:
            expires_at = _parse_timestamp(authority.expires_at)
        except ValueError:
            violations.append("authority expires_at is not a valid ISO-8601 timestamp")
        else:
            if expires_at is not None and expires_at <= datetime.now(timezone.utc):
                violations.append("authority is expired")

    if authority.trust_tier == "sender_constrained" and authority.proof_of_possession is False:
        violations.append("sender_constrained authority is missing proof_of_possession")

    if authority.has_capability_grant and authority.proof_of_possession is False:
        violations.append("capability-grant authority is not proof-of-possession bound")

    if _authority_has_capability_restrictions(authority):
        if not _authority_capabilities_allow(authority, execution_context.action):
            violations.append("authority capabilities do not allow this action")

    if authority.resource_scope:
        if not _authority_resource_scope_allows(authority, execution_context.action):
            violations.append("authority resource_scope does not allow this action")

    violations.extend(_authority_ref_violations(execution_context))

    return violations


def _effective_authority_trust_tier(authority: AuthorityContext) -> tuple[str | None, list[str]]:
    """Derive the trust tier from verified authority evidence, not a caller string."""
    from agentauth.receipts.assurance import TrustTier, parse_trust_tier, tier_ordinal

    issues: list[str] = []
    candidates: list[TrustTier] = [TrustTier.DECLARED]

    if authority.trust_tier:
        try:
            declared = parse_trust_tier(authority.trust_tier)
        except ValueError:
            issues.append(f"authority trust_tier {authority.trust_tier!r} is not recognized")
        else:
            if tier_ordinal(declared) <= tier_ordinal(TrustTier.SIGNED):
                candidates.append(declared)
            elif not authority.evidence_verified:
                issues.append(
                    f"authority trust_tier {authority.trust_tier!r} is declared but not "
                    "backed by verified identity evidence"
                )

    if authority.evidence_verified:
        if (
            authority.proof_of_possession is True
            and authority.presenter_key_hash
            and authority.has_capability_grant
        ):
            candidates.append(TrustTier.SENDER_CONSTRAINED)
        if authority.attestation_type and authority.workload_principal:
            candidates.append(TrustTier.WORKLOAD_ATTESTED)

    if not candidates:
        return None, issues
    return max(candidates, key=tier_ordinal).value, issues


def _authorization_approval_id(authorization: dict[str, Any]) -> str | None:
    approval_id = authorization.get("approval_id")
    if isinstance(approval_id, str) and approval_id:
        return approval_id
    approval = authorization.get("approval")
    if isinstance(approval, dict):
        nested = approval.get("approval_id")
        if isinstance(nested, str) and nested:
            return nested
    return None


def _authority_ref_violations(execution_context: ExecutionContext) -> list[str]:
    authority = execution_context.authority
    authorization = execution_context.authorization
    violations: list[str] = []

    if authority.approval_refs:
        approval_id = (
            _authorization_approval_id(authorization)
            if isinstance(authorization, dict)
            else None
        )
        if not approval_id or approval_id not in authority.approval_refs:
            violations.append(
                "authority approval_refs require a matching approval in authorization context"
            )

    if authority.budget_refs:
        budget_id = None
        if isinstance(authorization, dict):
            raw_budget = authorization.get("budget_id")
            if isinstance(raw_budget, str) and raw_budget:
                budget_id = raw_budget
        if budget_id and budget_id not in authority.budget_refs:
            violations.append(f"budget_id {budget_id!r} not in authority budget_refs")
        if (
            execution_context.action.side_effect_level
            != SideEffectLevel.READ_ONLY
            and not budget_id
        ):
            violations.append(
                "authority budget_refs set but authorization context lacks budget_id"
            )

    return violations


def _governed_runtime_violations(
    execution_context: ExecutionContext, policy: Policy | None
) -> list[str]:
    if policy is None:
        return []
    from agentauth.receipts.governed_runtime import evaluate_governed_tool_call

    authorization = execution_context.authorization
    gateway_token = None
    if isinstance(authorization, dict):
        gateway_token = authorization.get("gateway_token")
    return evaluate_governed_tool_call(
        action_name=execution_context.action.action_name,
        policy=policy.governed_runtime,
        gateway_token=str(gateway_token) if gateway_token else None,
    )


def _monitoring_violations(
    execution_context: ExecutionContext, policy: Policy | None
) -> list[str]:
    if policy is None or not policy.monitoring.enabled:
        return []
    authorization = execution_context.authorization
    if not isinstance(authorization, dict):
        return []
    raw = authorization.get("monitoring")
    if not isinstance(raw, dict):
        return []
    from agentauth.receipts.action_monitor import MonitoringSignal
    from agentauth.core.runtime import SideEffectLevel

    signal = MonitoringSignal.from_dict(raw)
    side_effect = execution_context.action.side_effect_level
    if not isinstance(side_effect, SideEffectLevel):
        side_effect = SideEffectLevel.EXTERNAL_SIDE_EFFECT
    _, block_threshold = policy.monitoring.thresholds_for(side_effect)
    if block_threshold is not None and signal.score >= block_threshold:
        return [
            f"monitoring score {signal.score:.2f} >= block threshold {block_threshold}"
        ]
    return []


def _authority_has_capability_restrictions(authority: AuthorityContext) -> bool:
    return bool(
        authority.capability_rules
        or authority.scope_claims
        or authority.capabilities
    )


def _action_candidates(action: ActionDescriptor) -> tuple[set[str], set[str]]:
    action_names = {action.action_name}
    if "." in action.action_name:
        action_names.add(action.action_name.rsplit(".", 1)[-1])

    resource_names: set[str] = set()
    if action.resource_type:
        resource_names.add(action.resource_type)
    if action.action_category and action.action_category != "custom":
        resource_names.add(action.action_category)
    if action.resource_ref:
        resource_names.add(action.resource_ref)
        parsed = action.parsed_resource_ref()
        if parsed is not None:
            resource_names.add(parsed.kind)

    return resource_names, action_names


def _authority_capabilities_allow(
    authority: AuthorityContext, action: ActionDescriptor
) -> bool:
    resource_names, action_names = _action_candidates(action)

    if authority.capability_rules:
        for item in authority.capability_rules:
            resource = str(item.get("resource", "")).strip()
            capability_action = str(item.get("action", "")).strip()
            if not resource or not capability_action:
                continue
            if resource not in resource_names:
                continue
            if capability_action == "*" or capability_action in action_names:
                return True

    candidate_scopes: set[str] = set(authority.scope_claims) | set(authority.capabilities)
    for scope in candidate_scopes:
        if ":" not in scope:
            if scope == action.action_name:
                return True
            continue
        resource, capability_action = scope.split(":", 1)
        if resource not in resource_names:
            continue
        if capability_action == "*" or capability_action in action_names:
            return True

    return False


def _authority_resource_scope_allows(
    authority: AuthorityContext, action: ActionDescriptor
) -> bool:
    file_patterns = [
        scope.removeprefix("file:")
        for scope in authority.resource_scope
        if scope.startswith("file:")
    ]
    structured_scopes = [
        scope for scope in authority.resource_scope if not scope.startswith("file:")
    ]

    paths = action_path_candidates(resource_ref=action.resource_ref)
    if file_patterns and paths:
        for path in paths:
            if not path_matches_any(path, file_patterns):
                return False
        if not structured_scopes:
            return True

    if not structured_scopes:
        if file_patterns and not paths:
            return False
        if not file_patterns:
            return False
        return True

    candidates: set[str] = set()
    if action.resource_ref:
        candidates.add(action.resource_ref)
    if action.resource_type:
        candidates.add(action.resource_type)
    if action.action_category and action.action_category != "custom":
        candidates.add(action.action_category)

    actual_ref = action.parsed_resource_ref() if action.resource_ref else None

    for scope in structured_scopes:
        if scope.startswith("resource:"):
            resource_value = scope.removeprefix("resource:")
            if resource_value in candidates:
                return True
            continue
        if scope in candidates:
            return True
        try:
            allowed_ref = parse_resource_ref(scope)
        except ValueError:
            continue
        if actual_ref is None:
            if allowed_ref.kind == (action.resource_type or "") and allowed_ref.value == "*":
                return True
            continue
        if allowed_ref.kind != actual_ref.kind:
            continue
        if allowed_ref.value == "*" or allowed_ref.value == actual_ref.value:
            return True
        if ("*" in allowed_ref.value or "?" in allowed_ref.value) and fnmatch.fnmatchcase(
            actual_ref.value, allowed_ref.value
        ):
            return True
        if paths and allowed_ref.kind in {"repo_read", "repo_write", "repo"}:
            for path in paths:
                pattern = allowed_ref.value
                if fnmatch.fnmatchcase(path, pattern):
                    return True

    return False


def _task_scope_violations(execution_context: ExecutionContext) -> list[str]:
    authorization = execution_context.authorization
    if not isinstance(authorization, dict):
        return []
    raw = authorization.get("task_scope")
    if not isinstance(raw, dict):
        return []
    scope = TaskScope.from_dict(raw)
    paths = action_path_candidates(resource_ref=execution_context.action.resource_ref)
    if not paths:
        return []

    violations: list[str] = []
    for path in paths:
        if scope.denied_paths and path_matches_any(path, scope.denied_paths):
            violations.append(f"task scope denied path {path!r}")
        elif scope.allowed_paths and not path_matches_any(path, scope.allowed_paths):
            violations.append(f"task scope does not allow path {path!r}")
    return violations


def _egress_violations(
    execution_context: ExecutionContext, policy: Policy | None
) -> list[str]:
    if policy is None or not policy.egress.enabled:
        return []
    from agentauth.receipts.egress import annotate_egress

    authorization = execution_context.authorization
    if not isinstance(authorization, dict):
        authorization = {}
        execution_context.authorization = authorization

    tool_name = execution_context.action.action_name.rsplit("/", 1)[-1]
    return annotate_egress(
        tool_name=tool_name,
        arguments=execution_context.input if isinstance(execution_context.input, dict) else {},
        policy=policy.egress,
        authority=execution_context.authority,
        authorization=authorization,
    )


def _credential_access_violations(
    execution_context: ExecutionContext, policy: Policy | None
) -> list[str]:
    if policy is None or not policy.credential_access.enabled:
        return []
    from agentauth.receipts.credential_access import annotate_credential_access

    authorization = execution_context.authorization
    if not isinstance(authorization, dict):
        authorization = {}
        execution_context.authorization = authorization
    tool_name = execution_context.action.action_name.rsplit("/", 1)[-1]
    return annotate_credential_access(
        tool_name=tool_name,
        arguments=execution_context.input if isinstance(execution_context.input, dict) else {},
        policy=policy.credential_access,
        authority=execution_context.authority,
        authorization=authorization,
    )


def _artifact_guard_violations(
    execution_context: ExecutionContext, policy: Policy | None
) -> list[str]:
    if policy is None or not policy.artifact_guard.enabled:
        return []
    from agentauth.receipts.artifact_guard import annotate_artifact_publication

    authorization = execution_context.authorization
    if not isinstance(authorization, dict):
        authorization = {}
        execution_context.authorization = authorization
    tool_name = execution_context.action.action_name.rsplit("/", 1)[-1]
    return annotate_artifact_publication(
        tool_name=tool_name,
        arguments=execution_context.input if isinstance(execution_context.input, dict) else {},
        policy=policy.artifact_guard,
        authority=execution_context.authority,
        authorization=authorization,
        payload_text=None,
    )


def _artifact_payload_violations(
    execution_context: ExecutionContext, policy: Policy | None
) -> list[str]:
    if policy is None or not policy.artifact_guard.enabled:
        return []
    if not policy.artifact_guard.deny_secret_in_artifacts:
        return []
    from agentauth.receipts.artifact_guard import annotate_artifact_publication

    authorization = execution_context.authorization
    if not isinstance(authorization, dict):
        authorization = {}
        execution_context.authorization = authorization
    tool_name = execution_context.action.action_name.rsplit("/", 1)[-1]
    payload = execution_context.output
    payload_text = json.dumps(payload, sort_keys=True) if isinstance(payload, dict) else (
        str(payload) if payload is not None else None
    )
    return annotate_artifact_publication(
        tool_name=tool_name,
        arguments=execution_context.input if isinstance(execution_context.input, dict) else {},
        policy=policy.artifact_guard,
        authority=execution_context.authority,
        authorization=authorization,
        payload_text=payload_text,
    )


def pre_execution_violations(
    execution_context: ExecutionContext,
    policy: Policy | None,
    *,
    compiled_resource_scope: list[str] | None = None,
) -> list[str]:
    """Authority, task-scope, and monitoring violations evaluated before side effects."""
    violations: list[str] = []
    if compiled_resource_scope and not execution_context.authority.resource_scope:
        execution_context.authority.resource_scope = list(compiled_resource_scope)
    violations.extend(_authority_violations(execution_context, policy))
    violations.extend(_task_scope_violations(execution_context))
    violations.extend(_governed_runtime_violations(execution_context, policy))
    violations.extend(_monitoring_violations(execution_context, policy))
    violations.extend(_egress_violations(execution_context, policy))
    violations.extend(_credential_access_violations(execution_context, policy))
    violations.extend(_artifact_guard_violations(execution_context, policy))
    return violations


def post_execution_violations(
    execution_context: ExecutionContext,
    policy: Policy | None,
) -> list[str]:
    """Artifact payload and other post-side-effect policy checks."""
    violations: list[str] = []
    violations.extend(_artifact_payload_violations(execution_context, policy))
    return violations


@dataclass
class ReservationResult:
    """Result of a pre-execution budget reservation check (L3-8)."""

    outcome: DecisionOutcome
    budget_effects: list[BudgetEffect] = field(default_factory=list)
    notes: str | None = None


ReservationCallback = Callable[
    [ExecutionContext, dict[str, Any], list[str]],
    ReservationResult | None,
]


def noop_reservation_callback(
    _ctx: ExecutionContext,
    _output: dict[str, Any],
    _violations: list[str],
) -> None:
    """Default no-op reservation hook."""
    return None
