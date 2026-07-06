from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import time
from typing import Any

from agentauth.core.decision import DecisionResult, Obligation
from agentauth.core.delegation import DelegationToken, verify_delegation_chain
from agentauth.core.hash_util import hash_canonical_json
from agentauth.receipts.proof import DecisionOutcome
from agentauth.core.runtime import (
    ActionDescriptor,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)
from agentauth.receipts.wrapper import AgentWrapper, RunResult

ToolHandler = Callable[[dict[str, Any]], Any]
AsyncToolHandler = Callable[[dict[str, Any]], Awaitable[Any]]

MCP_TOOL_CALL_ACTION = "mcp.tools/call"

_PERF_BUDGETS_MS: dict[str, float] = {
    "broker_pre_tool_ms": 50.0,
    "monitor_ms": 25.0,
    "governor_ms": 25.0,
    "record_ms": 50.0,
}


def _perf_budget_warnings(timings_ms: dict[str, float]) -> list[str]:
    warnings: list[str] = []
    for key, budget in _PERF_BUDGETS_MS.items():
        value = timings_ms.get(key)
        if value is None:
            continue
        if value > budget:
            warnings.append(f"perf_budget_exceeded:{key}:{value:.2f}ms>{budget:.2f}ms")
    return warnings


@dataclass
class McpAuthorizationContext:
    """Authorization context stored on the audit chain for MCP tool calls."""

    mode: str
    principal: str
    organization: str
    mcp_server: str
    tool_name: str
    arguments_hash: str
    tool_identity_hash: str | None = None
    tool_description_hash: str | None = None
    tool_schema_hash: str | None = None
    egress: dict[str, Any] | None = None
    delegation_id: str | None = None
    delegation_depth: int = 0
    signed_delegation: dict[str, Any] | None = None
    prove_policy: bool = False
    blocked: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "protocol": "mcp",
            "mode": self.mode,
            "principal": self.principal,
            "organization": self.organization,
            "mcp_server": self.mcp_server,
            "tool_name": self.tool_name,
            "arguments_hash": self.arguments_hash,
            "tool_identity_hash": self.tool_identity_hash,
            "tool_description_hash": self.tool_description_hash,
            "tool_schema_hash": self.tool_schema_hash,
            "egress": self.egress,
            "delegation_id": self.delegation_id,
            "delegation_depth": self.delegation_depth,
            "prove_policy": self.prove_policy,
            "blocked": self.blocked,
        }
        if self.signed_delegation is not None:
            payload["signed_delegation"] = self.signed_delegation
        return payload


@dataclass
class ToolCallResult:
    """Receipt bundle for a single MCP tool invocation."""

    tool_name: str
    arguments: dict[str, Any]
    output: dict[str, Any]
    blocked: bool
    proof: Any
    audit_record: Any | None
    decision: DecisionResult
    execution_context: ExecutionContext
    policy_violations: list[str] = field(default_factory=list)
    recommended_action: str | None = None
    monitoring: dict[str, Any] | None = None

    @property
    def decision_outcome(self) -> DecisionOutcome:
        return self.decision.outcome

    @property
    def policy_satisfied(self) -> bool:
        return self.decision.policy_satisfied

    @property
    def authority_version(self) -> int:
        return self.decision.authority_version

    @property
    def session_id(self) -> str | None:
        return self.decision.session_id

    @property
    def obligations(self) -> list[Obligation]:
        return self.decision.obligations

    def to_legacy_dict(self) -> dict[str, Any]:
        """Flat dict for integrations that predate ``ToolCallResult.decision``."""
        return {
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "output": self.output,
            "blocked": self.blocked,
            "policy_violations": list(self.policy_violations),
            "policy_satisfied": self.policy_satisfied,
            "decision_outcome": self.decision_outcome.value,
            "recommended_action": self.recommended_action,
            "obligations": [item.to_dict() for item in self.obligations],
        }

    @classmethod
    def from_run(
        cls,
        tool_name: str,
        arguments: dict[str, Any],
        run: RunResult,
        *,
        blocked: bool,
    ) -> ToolCallResult:
        return cls(
            tool_name=tool_name,
            arguments=arguments,
            output=run.output,
            blocked=blocked,
            proof=run.proof,
            audit_record=run.audit_record,
            decision=run.decision,
            execution_context=run.execution_context,
            policy_violations=run.policy_violations,
            recommended_action=run.recommended_action,
            monitoring=getattr(run.execution_context, "monitoring", None),
        )


class ReceiptedMcpGateway:
    """
    Wrap MCP-style tool calls with policy checks, delegation, and audit receipts.

    Register handlers with `register_tool`, then invoke via `call_tool` (sync) or
    `call_tool_async` (async handlers / MCP SDK bridge).
    """

    def __init__(
        self,
        agent: AgentWrapper,
        *,
        server_name: str = "default",
        delegation: DelegationToken | None = None,
        signed_delegation: dict[str, Any] | None = None,
        allow_unsafe_execution: bool = False,
        session_id: str | None = None,
        repo_root: str | None = None,
        query_id: str | None = None,
        behavior_monitor: Any | None = None,
        sandbox_governor: Any | None = None,
        authority: AuthorityContext | dict[str, Any] | None = None,
        authority_id: str | None = None,
        authority_version: int = 1,
        commit_signing_key: Any | None = None,
        commit_ttl_seconds: int = 300,
        monitor_trace_window: int = 8,
        resource_ref_resolvers: dict[str, Any] | None = None,
    ) -> None:
        from agentauth.receipts.behavior_monitor import NullBehaviorMonitor
        from agentauth.receipts.sandbox_governor import NullSandboxGovernor

        self.agent = agent
        self.server_name = server_name
        self.delegation = delegation
        self.signed_delegation = signed_delegation
        self.allow_unsafe_execution = allow_unsafe_execution
        self.session_id = session_id
        self._query_id = query_id
        self._repo_root: str | None = repo_root
        self._chunk_index: Any | None = None
        self._capability_lease: Any | None = None
        self._tool_entity_index: Any | None = None
        self._tool_capability_lease: Any | None = None
        self._tool_call_budget: Any | None = None
        self._value_budget: Any | None = None
        self._tool_specs: dict[str, Any] = {}
        self.behavior_monitor = behavior_monitor or NullBehaviorMonitor()
        self.sandbox_governor = sandbox_governor or NullSandboxGovernor()
        if authority is None:
            cert = getattr(self.agent, "certificate", None)
            agent_id = getattr(cert, "agent_id", None) if cert is not None else None
            self._authority = AuthorityContext(
                authority_id=authority_id or str(agent_id or "unknown-agent"),
                authority_version=authority_version,
                session_id=session_id,
            )
        elif isinstance(authority, AuthorityContext):
            self._authority = authority
        else:
            self._authority = AuthorityContext.from_dict(authority)
        self._commit_signing_key = commit_signing_key
        self._commit_ttl_seconds = int(commit_ttl_seconds)
        self._used_commit_tokens: set[str] = set()
        self._monitor_trace_window = int(monitor_trace_window)
        self._monitor_trace: list[Any] = []
        self._resource_ref_resolvers = dict(resource_ref_resolvers or {})
        self._handlers: dict[str, ToolHandler] = {}
        self._async_handlers: dict[str, AsyncToolHandler] = {}
        self._tool_descriptions: dict[str, str] = {}
        self._tool_schemas: dict[str, dict[str, Any]] = {}
        from agentauth.receipts.tool_pinning import ToolPinRegistry

        self._tool_pin_registry = ToolPinRegistry()

    def _authority_copy(self) -> AuthorityContext:
        return AuthorityContext.from_dict(self._authority.to_dict())

    def _update_authority_from_context(self, ctx: ExecutionContext) -> None:
        self._authority = AuthorityContext.from_dict(ctx.authority.to_dict())

    def authority(self) -> AuthorityContext:
        return self._authority_copy()

    def set_authority(self, authority: AuthorityContext | dict[str, Any]) -> AuthorityContext:
        if isinstance(authority, AuthorityContext):
            self._authority = authority
        else:
            self._authority = AuthorityContext.from_dict(authority)
        return self._authority_copy()

    def query_id(self) -> str | None:
        return self._query_id

    def set_query_id(self, query_id: str | None) -> None:
        self._query_id = query_id

    def revoke_permits(self, *, bump_authority_version: bool = True) -> AuthorityContext:
        """Invalidate previously issued permits by bumping ``authority.permit_epoch``."""
        self._authority.permit_epoch = int(self._authority.permit_epoch) + 1
        if bump_authority_version:
            self._authority.authority_version = int(self._authority.authority_version) + 1
        return self._authority_copy()

    def issue_commit_token(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        ttl_seconds: int | None = None,
        signing_key: Any | None = None,
    ) -> dict[str, Any]:
        """Mint a signed commit token for an irreversible tool call."""
        from agentauth.capabilities.commit import issue_commit_token

        key = signing_key or self._commit_signing_key
        if key is None:
            raise ValueError("commit_signing_key not configured")
        ttl = int(ttl_seconds if ttl_seconds is not None else self._commit_ttl_seconds)
        if ttl <= 0:
            raise ValueError("ttl_seconds must be > 0")
        args = dict(arguments or {})
        args.pop("_commit_token", None)
        ctx = ExecutionContext(
            action=self._action_descriptor(tool_name, args),
            input=args,
            authority=self._authority_copy(),
            query_id=self._query_id,
            authorization=None,
            touched_resources=[f"mcp://{self.server_name}/{tool_name}"],
        )
        return issue_commit_token(ctx, key=key, ttl_seconds=ttl).to_dict()

    def renew_lease(
        self,
        *,
        ttl_seconds: int,
        bump_authority_version: bool = True,
        query_id: str | None = None,
        call_budget: int | None = None,
    ) -> AuthorityContext:
        """Grant/renew a short-lived capability lease on the gateway authority."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        self._authority.expires_at = expires_at.isoformat()
        if query_id is not None:
            self._authority.lease_query_id = query_id
        if call_budget is not None:
            self._authority.lease_remaining_calls = int(call_budget)
        if bump_authority_version:
            self._authority.authority_version = int(self._authority.authority_version) + 1
        return self._authority_copy()

    def bind_repo(self, repo_root: str) -> None:
        """Index a repo for offline chunk/graph scoping (call once per session)."""
        from agentauth.capabilities.scoping import build_repo_chunk_index

        self._repo_root = repo_root
        self._chunk_index = build_repo_chunk_index(repo_root)

    def mint_capability_lease(
        self,
        goal: dict[str, Any] | Any,
        *,
        top_k: int = 12,
    ) -> Any:
        """Mint a goal-bound lease and apply it to gateway + agent resource_scope."""
        from agentauth.capabilities.scoping import GoalSpec, build_capability_lease
        from agentauth.capabilities.scoping.capability_scope import apply_lease_to_authority

        if self._chunk_index is None:
            if not self._repo_root:
                raise ValueError("bind_repo() required before mint_capability_lease()")
            self.bind_repo(self._repo_root)
        spec = goal if isinstance(goal, GoalSpec) else GoalSpec.from_dict(goal)
        if self._query_id and not spec.query_id:
            spec = GoalSpec(
                query_id=self._query_id,
                summary=spec.summary,
                allow_resources=list(spec.allow_resources),
                structured_intent=dict(spec.structured_intent),
            )
        lease = build_capability_lease(self._chunk_index, spec, top_k=top_k)
        self._capability_lease = lease
        apply_lease_to_authority(self._authority, lease)
        return lease

    def active_capability_lease(self) -> Any | None:
        return self._capability_lease

    def mint_tool_capability_lease(
        self,
        goal: dict[str, Any] | Any,
        *,
        entities: list[Any] | None = None,
        membership_edges: list[tuple[str, str]] | None = None,
        budget_config: Any | None = None,
        top_k: int = 10,
    ) -> Any:
        """Mint a goal-bound tool/target lease + call budget from this
        gateway's own registered tools, and apply to gateway state.

        Kept separate from ``mint_capability_lease`` (file scoping): that
        method requires ``bind_repo()`` and is fundamentally repo-shaped;
        this one needs no repo and is built purely from registered tools +
        a caller-supplied entity directory. Note this only sees tools
        registered on *this* gateway -- for a multi-gateway setup where a
        goal should also see (and exclude) tools registered on sibling
        gateways, mint once against the union and call
        ``set_tool_capability_lease`` on each gateway instead of calling
        this method on each one independently.
        """
        from agentauth.capabilities.scoping.goal import GoalSpec
        from agentauth.capabilities.scoping.tools import (
            ToolCallBudget,
            ToolCallBudgetConfig,
            build_tool_capability_lease,
            build_tool_entity_index,
        )

        spec = goal if isinstance(goal, GoalSpec) else GoalSpec.from_dict(goal)
        if self._query_id and not spec.query_id:
            spec = GoalSpec(
                query_id=self._query_id,
                summary=spec.summary,
                allow_resources=list(spec.allow_resources),
                structured_intent=dict(spec.structured_intent),
            )
        index = build_tool_entity_index(
            tools=list(self._tool_specs.values()),
            entities=list(entities or []),
            membership_edges=list(membership_edges or []),
        )
        self._tool_entity_index = index
        lease = build_tool_capability_lease(index, spec, top_k=top_k)
        self._tool_capability_lease = lease
        self._tool_call_budget = ToolCallBudget(config=budget_config or ToolCallBudgetConfig())
        return lease

    def set_tool_capability_lease(self, lease: Any, budget: Any) -> None:
        """Apply an externally-minted lease/budget (e.g. one built from the
        union of tools across several sibling gateways) to this gateway."""
        self._tool_capability_lease = lease
        self._tool_call_budget = budget

    def set_value_budget(self, value_budget: Any) -> None:
        """Apply a shared cumulative value budget (see receipts/value_budget.py).
        Share one instance across sibling gateways so spend accumulates across
        tools/servers -- e.g. the legacy connector debits the same payout
        budget as the governed tool."""
        self._value_budget = value_budget

    def active_tool_capability_lease(self) -> Any | None:
        return self._tool_capability_lease

    def registered_tool_specs(self) -> dict[str, Any]:
        """This gateway's own ``ToolSpec`` registry (public accessor for
        multi-gateway callers minting one shared lease from the union of
        several gateways' tools)."""
        return dict(self._tool_specs)

    def active_tool_call_budget(self) -> Any | None:
        return self._tool_call_budget

    def register_tool(
        self,
        name: str,
        handler: ToolHandler,
        *,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
        owner_role: str | None = None,
        target_arg_keys: tuple[str, ...] | None = None,
        trust_tier: str = "primary",
        side_effect_level: SideEffectLevel | None = None,
    ) -> None:
        self._handlers[name] = handler
        if description is not None:
            self._tool_descriptions[name] = description
        if input_schema is not None:
            self._tool_schemas[name] = input_schema
        self._register_tool_spec(
            name,
            description=description,
            owner_role=owner_role,
            target_arg_keys=target_arg_keys,
            trust_tier=trust_tier,
            side_effect_level=side_effect_level,
        )
        if self.agent.policy.tool_pinning.enabled:
            self._tool_pin_registry.pin(
                self.server_name,
                name,
                description=description,
                input_schema=input_schema,
            )

    def register_tool_async(
        self,
        name: str,
        handler: AsyncToolHandler,
        *,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
        owner_role: str | None = None,
        target_arg_keys: tuple[str, ...] | None = None,
        trust_tier: str = "primary",
        side_effect_level: SideEffectLevel | None = None,
    ) -> None:
        self._async_handlers[name] = handler
        if description is not None:
            self._tool_descriptions[name] = description
        if input_schema is not None:
            self._tool_schemas[name] = input_schema
        self._register_tool_spec(
            name,
            description=description,
            owner_role=owner_role,
            target_arg_keys=target_arg_keys,
            trust_tier=trust_tier,
            side_effect_level=side_effect_level,
        )
        if self.agent.policy.tool_pinning.enabled:
            self._tool_pin_registry.pin(
                self.server_name,
                name,
                description=description,
                input_schema=input_schema,
            )

    def _register_tool_spec(
        self,
        name: str,
        *,
        description: str | None,
        owner_role: str | None,
        target_arg_keys: tuple[str, ...] | None,
        trust_tier: str,
        side_effect_level: SideEffectLevel | None = None,
    ) -> None:
        from agentauth.capabilities.scoping.tools import ToolSpec

        # _action_descriptor's own classification is unreliable for this
        # purpose: it can classify plain read tools as EXTERNAL_SIDE_EFFECT
        # rather than READ_ONLY (confirmed via a live run where a genuine
        # read tool was wrongly enforced as if it were a write). Trust an
        # explicit caller-supplied level over the auto-classified one.
        resolved_side_effect = side_effect_level
        if resolved_side_effect is None:
            action = self._action_descriptor(name, {})
            resolved_side_effect = action.side_effect_level
        self._tool_specs[name] = ToolSpec(
            name=name,
            description=description or self._tool_descriptions.get(name, ""),
            owner_role=owner_role or self.server_name,
            side_effect_level=resolved_side_effect,
            target_arg_keys=tuple(target_arg_keys or ()),
            trust_tier=trust_tier,
        )

    def _collect_violations(
        self,
        tool_name: str,
        *,
        arguments: dict[str, Any] | None = None,
        tool_witness_present: bool = False,
    ) -> list[str]:
        action = self._action_descriptor(tool_name, arguments or {})
        violations: list[str] = []
        uses_capability_auth = self.agent.capability_authorizer is not None
        if self.agent.capability_authorizer is not None:
            violations.extend(self.agent.authorize_action(action))
        else:
            from agentauth.core.authority_binding import AuthorityBinding

            binding = self.agent.default_authority_binding
            if isinstance(binding, AuthorityBinding) and (
                binding.has_capability_grant and binding.evidence_verified
            ):
                uses_capability_auth = True
                violations.extend(self.agent.authorize_action(action))
        violations.extend(self.agent.policy.check_tool(tool_name))
        if not uses_capability_auth:
            scope = self.agent.certificate.principal.scope
            if scope and tool_name not in scope:
                violations.append(f"tool {tool_name} not in certificate principal scope")
        violations.extend(
            verify_delegation_chain(
                self.delegation,
                action=action,
                signed_envelope=self.signed_delegation,
                require_signature=self.agent.mode != "shadow",
            )
        )
        from agentauth.receipts.tool_pinning import tool_pinning_violations

        violations.extend(
            tool_pinning_violations(
                policy=self.agent.policy.tool_pinning,
                registry=self._tool_pin_registry,
                server=self.server_name,
                tool=tool_name,
                description=self._tool_descriptions.get(tool_name),
                input_schema=self._tool_schemas.get(tool_name),
                tool_witness_present=tool_witness_present,
            )
        )
        return violations

    def _auth_context(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        blocked: bool,
        authorization_extras: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        egress_payload = None
        if isinstance(authorization_extras, dict):
            raw = authorization_extras.get("egress")
            if isinstance(raw, dict):
                egress_payload = raw
        ctx = McpAuthorizationContext(
            mode=self.agent.mode,
            principal=self.agent.certificate.principal.principal_id,
            organization=self.agent.certificate.principal.organization,
            mcp_server=self.server_name,
            tool_name=tool_name,
            arguments_hash=hash_canonical_json(arguments),
            tool_identity_hash=hash_canonical_json(
                {"server": self.server_name, "tool": tool_name}
            ),
            tool_description_hash=(
                hash_canonical_json({"description": self._tool_descriptions[tool_name]})
                if tool_name in self._tool_descriptions
                else None
            ),
            tool_schema_hash=(
                hash_canonical_json(self._tool_schemas[tool_name])
                if tool_name in self._tool_schemas
                else None
            ),
            egress=egress_payload,
            delegation_id=str(self.delegation.delegation_id) if self.delegation else None,
            delegation_depth=self.delegation.depth if self.delegation else 0,
            signed_delegation=self.signed_delegation,
            prove_policy=self.agent.prove_policy,
            blocked=blocked,
        )
        payload = ctx.to_dict()
        if isinstance(authorization_extras, dict):
            for key, value in authorization_extras.items():
                if key != "egress" and key not in payload:
                    payload[key] = value
        return payload

    def _should_block(
        self, violations: list[str], action: ActionDescriptor | None = None
    ) -> bool:
        if not violations:
            return False
        if self.agent.mode == "bounded_auto":
            return True
        if self.allow_unsafe_execution:
            return False
        if action and action.side_effect_level == SideEffectLevel.READ_ONLY:
            return False
        if self.agent.mode in {"shadow", "recommend"}:
            return True
        return False

    def _scope_step_up_requested(self, violations: list[str]) -> bool:
        """True when violations indicate missing scope that should trigger step-up."""
        return any(
            "authority resource_scope does not allow this action" in v for v in violations
        )

    def _tool_output(
        self,
        tool_name: str,
        *,
        status: str,
        result: Any = None,
        violations: list[str] | None = None,
    ) -> dict[str, Any]:
        out: dict[str, Any] = {
            "tool": tool_name,
            "mcp_server": self.server_name,
            "status": status,
        }
        if result is not None:
            out["result"] = result
        if violations:
            out["violations"] = violations
        return out

    def _file_path_from_arguments(self, arguments: dict[str, Any]) -> str | None:
        for key in ("path", "file_path", "filepath", "target", "file"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _action_descriptor(
        self, tool_name: str, arguments: dict[str, Any] | None = None
    ) -> ActionDescriptor:
        from agentauth.receipts.egress import network_action_descriptor

        args = dict(arguments or {})
        resolver = self._resource_ref_resolvers.get(tool_name)
        if resolver is not None:
            try:
                resource_ref = resolver(args)
                if resource_ref:
                    return ActionDescriptor(
                        action_name=f"{MCP_TOOL_CALL_ACTION}/{tool_name}",
                        action_category="mcp_tool_call",
                        resource_type="mcp_tool",
                        resource_ref=resource_ref,
                        side_effect_level=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
                    )
            except Exception:
                pass

        file_path = self._file_path_from_arguments(args)
        if file_path:
            normalized = file_path.replace("\\", "/").lstrip("/")
            fallback = f"repo://{normalized}"
        else:
            fallback = f"{self.server_name}:{tool_name}"
        return network_action_descriptor(
            tool_name,
            arguments,
            policy=self.agent.policy.egress if self.agent.policy else None,
            fallback_resource_ref=fallback,
        )

    def _tool_execution_context(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> ExecutionContext:
        action = self._action_descriptor(tool_name, arguments)
        authority = self._authority_copy()
        if self.agent.default_authority_binding is not None:
            bound = self.agent.default_authority_binding.to_authority_context(
                session_id=self.session_id,
                resource_scope=self.agent.compiled_resource_scope or None,
            )
            if bound.resource_scope and not authority.resource_scope:
                authority.resource_scope = list(bound.resource_scope)
        elif self.agent.compiled_resource_scope and not authority.resource_scope:
            authority.resource_scope = list(self.agent.compiled_resource_scope)

        authorization: dict[str, Any] | None = None
        if self.agent.task_scope is not None:
            authorization = {"task_scope": self.agent.task_scope.to_dict()}
        if authorization is None:
            authorization = {}
        authorization["gateway_token"] = "receipted_mcp_gateway"

        return ExecutionContext(
            action=action,
            input=arguments,
            authority=authority,
            query_id=self._query_id,
            authorization=authorization,
        )

    def _pre_execution_violations(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[list[str], dict[str, Any] | None, ExecutionContext]:
        from agentauth.receipts.policy_engine import pre_execution_violations

        execution_context = self._tool_execution_context(tool_name, arguments)
        monitoring_payload: dict[str, Any] | None = None
        monitor = self.agent.session_monitor
        if monitor is not None and self.agent.policy.monitoring.enabled:
            signal = monitor.evaluate(execution_context, commit=False)
            monitoring_payload = signal.to_dict()
            authorization = dict(execution_context.authorization or {})
            authorization["monitoring"] = monitoring_payload
            execution_context.authorization = authorization

        violations = pre_execution_violations(
            execution_context,
            self.agent.policy,
            compiled_resource_scope=self.agent.compiled_resource_scope or None,
        )
        from agentauth.capabilities.scoping.lease_enforcement import capability_lease_violations

        violations.extend(
            capability_lease_violations(
                self._capability_lease,
                tool_name=tool_name,
                arguments=arguments,
                side_effect=execution_context.action.side_effect_level,
                resource_ref=execution_context.action.resource_ref,
            )
        )
        from agentauth.capabilities.scoping.tools import tool_capability_lease_violations

        # Prefer the registered ToolSpec's side_effect_level over the
        # per-call auto-classified one: _action_descriptor's classification
        # is unreliable for this purpose (see _register_tool_spec) and a
        # caller may have registered an explicit override.
        registered_spec = self._tool_specs.get(tool_name)
        lease_side_effect = (
            registered_spec.side_effect_level
            if registered_spec is not None
            else execution_context.action.side_effect_level
        )
        violations.extend(
            tool_capability_lease_violations(
                self._tool_capability_lease,
                self._tool_call_budget,
                tool_name=tool_name,
                arguments=arguments,
                side_effect=lease_side_effect,
                resource_ref=execution_context.action.resource_ref,
            )
        )
        if self._value_budget is not None:
            allowed, reason = self._value_budget.would_allow(tool_name, arguments)
            if not allowed:
                violations.append(
                    f"value budget {reason}: tool={tool_name!r}"
                )
        return violations, monitoring_payload, execution_context

    def _monitoring_violations(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[list[str], dict[str, Any] | None]:
        violations, monitoring_payload, _execution_context = self._pre_execution_violations(
            tool_name, arguments
        )
        monitoring_only = [
            item
            for item in violations
            if item.startswith("monitoring score")
        ]
        return monitoring_only, monitoring_payload

    def _apply_sandbox_governor(
        self,
        execution_context: ExecutionContext,
        violations: list[str],
        *,
        commit_token_raw: Any | None = None,
    ) -> tuple[list[str], Any | None]:
        from agentauth.receipts.behavior_monitor import evaluate_behavior_monitor
        from agentauth.capabilities.commit import SignedCommitToken, verify_commit_token
        from agentauth.receipts.monitor_contract import build_monitor_input
        from agentauth.receipts.permit import SignedToolPermit, verify_tool_permit
        from agentauth.receipts.sandbox_governor import (
            SandboxEnforcement,
            apply_authority_patch,
        )

        contract = build_monitor_input(execution_context, recent=self._monitor_trace)
        monitor = evaluate_behavior_monitor(
            self.behavior_monitor, ctx=execution_context, contract=contract
        )
        if monitor is not None:
            monitor = monitor.bounded().with_trace_commitment(contract.trace_commitment())
            execution_context.monitoring = monitor.to_dict()
        if self._monitor_trace_window > 0:
            self._monitor_trace.append(contract.proposed)
            if len(self._monitor_trace) > self._monitor_trace_window:
                self._monitor_trace = self._monitor_trace[-self._monitor_trace_window :]

        authority_before = execution_context.authority.to_dict()
        governor = self.sandbox_governor.decide(
            execution_context,
            monitor=monitor,
            structural_violations=violations,
        )
        merged = [*violations, *list(governor.extra_violations)]
        execution_context.sandboxing = {
            "enforcement": governor.enforcement.value,
            "authority_before": {
                "authority_version": authority_before.get("authority_version"),
                "expires_at": authority_before.get("expires_at"),
                "lease_query_id": authority_before.get("lease_query_id"),
                "lease_remaining_calls": authority_before.get("lease_remaining_calls"),
                "permit_epoch": authority_before.get("permit_epoch"),
            },
            "authority_patch": governor.authority_patch,
            "tool_permit": governor.tool_permit,
            "applied_patch": governor.enforcement == SandboxEnforcement.ALLOW,
        }
        if governor.enforcement == SandboxEnforcement.ALLOW:
            apply_authority_patch(execution_context.authority, governor.authority_patch)
            self._update_authority_from_context(execution_context)

        blocked = governor.is_blocking()
        if not blocked and governor.tool_permit is not None:
            try:
                signed = SignedToolPermit.from_dict(dict(governor.tool_permit))
            except Exception:
                merged = [*merged, "sandbox: invalid tool permit encoding"]
                blocked = True
            else:
                ok, reason = verify_tool_permit(signed, ctx=execution_context)
                if not ok:
                    merged = [*merged, f"sandbox: invalid tool permit ({reason})"]
                    blocked = True

        if not blocked and governor.commit_required and commit_token_raw is None:
            merged = [*merged, "sandbox: missing commit token (_commit_token)"]
            blocked = True

        if commit_token_raw is not None and isinstance(commit_token_raw, dict):
            try:
                signed_commit = SignedCommitToken.from_dict(dict(commit_token_raw))
            except Exception:
                merged = [*merged, "sandbox: invalid commit token encoding"]
                blocked = True
            else:
                ok, reason = verify_commit_token(signed_commit, ctx=execution_context)
                if not ok:
                    merged = [*merged, f"sandbox: invalid commit token ({reason})"]
                    blocked = True
                elif signed_commit.token.token_id in self._used_commit_tokens:
                    merged = [*merged, "sandbox: commit token replay detected"]
                    blocked = True
                else:
                    self._used_commit_tokens.add(signed_commit.token.token_id)

        if blocked and governor.is_blocking():
            return merged, governor
        if blocked:
            return merged, governor
        return merged, governor

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> ToolCallResult:
        """Invoke a registered tool and append an MCP audit record + execution proof."""
        args = dict(arguments or {})
        commit_token_raw = args.pop("_commit_token", None)
        violations = self._collect_violations(name, arguments=args)
        pre_violations, monitoring_payload, execution_context = self._pre_execution_violations(
            name, args
        )
        violations.extend(pre_violations)
        violations, governor = self._apply_sandbox_governor(
            execution_context, violations, commit_token_raw=commit_token_raw
        )
        action = self._action_descriptor(name, args)
        blocked = self._should_block(violations, action)
        if governor is not None and governor.is_blocking():
            blocked = True
        touched_resources = [f"mcp://{self.server_name}/{name}"]
        file_path = self._file_path_from_arguments(args)
        if file_path:
            touched_resources.append(f"file:{file_path}")

        if name not in self._handlers:
            violations = [*violations, f"unregistered tool handler: {name}"]
            blocked = True

        if blocked:
            from agentauth.receipts.sandbox_governor import SandboxEnforcement

            outcome = (
                governor.decision_outcome()
                if governor is not None and governor.is_blocking()
                else DecisionOutcome.DENY
            )
            status = "blocked"
            if governor is not None and governor.enforcement == SandboxEnforcement.STEP_UP:
                status = "step_up_required"
            elif self._scope_step_up_requested(violations):
                status = "step_up_required"
            output = self._tool_output(name, status=status, violations=violations)
            auth_extras: dict[str, Any] = {}
            if monitoring_payload is not None:
                auth_extras["monitoring"] = monitoring_payload
            if isinstance(execution_context.authorization, dict):
                auth_extras.update(execution_context.authorization)
            auth = self._auth_context(
                name, args, blocked=True, authorization_extras=auth_extras
            )
            execution_context.authorization = auth
            execution_context.touched_resources = touched_resources
            run = self.agent.record(
                action=action,
                context=execution_context,
                output=output,
                extra_violations=violations,
                check_policy_output=False,
                decision_outcome=outcome,
                session_id=self.session_id,
            )
            recommended = "deny_tool" if self.agent.mode == "recommend" and violations else None
            return ToolCallResult(
                tool_name=name,
                arguments=args,
                output=output,
                blocked=True,
                proof=run.proof,
                audit_record=run.audit_record,
                decision=run.decision,
                execution_context=run.execution_context,
                policy_violations=violations,
                recommended_action=recommended,
                monitoring=run.execution_context.monitoring,
            )

        from agentauth.capabilities.scoping.tools import commit_tool_call_budget

        commit_tool_call_budget(
            self._tool_call_budget,
            tool_name=name,
            arguments=args,
            side_effect=(
                self._tool_specs[name].side_effect_level
                if name in self._tool_specs
                else execution_context.action.side_effect_level
            ),
        )
        if self._value_budget is not None:
            self._value_budget.commit(name, args)

        raw = self._handlers[name](args)
        output = self._tool_output(name, status="ok", result=raw)
        if isinstance(raw, dict):
            violations = [*violations, *self.agent.policy.check_output(raw)]

        execution_context.output = output
        from agentauth.receipts.policy_engine import post_execution_violations

        post_violations = post_execution_violations(execution_context, self.agent.policy)
        if post_violations:
            violations = [*violations, *post_violations]
            blocked = self._should_block(violations, action)

        auth_extras: dict[str, Any] = {}
        if isinstance(execution_context.authorization, dict):
            auth_extras.update(execution_context.authorization)
        auth = self._auth_context(
            name, args, blocked=blocked, authorization_extras=auth_extras
        )
        execution_context.authorization = auth
        execution_context.touched_resources = touched_resources
        run = self.agent.record(
            action=action,
            context=execution_context,
            output=output,
            extra_violations=violations,
            session_id=self.session_id,
            decision_outcome=DecisionOutcome.DENY if blocked else None,
        )
        recommended = None
        if self.agent.mode == "recommend" and violations:
            recommended = "review_tool_output"

        return ToolCallResult.from_run(name, args, run, blocked=blocked)

    async def call_tool_async(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> ToolCallResult:
        """Async variant for MCP SDK handlers."""
        args = dict(arguments or {})
        commit_token_raw = args.pop("_commit_token", None)
        violations = self._collect_violations(name, arguments=args)
        pre_violations, monitoring_payload, execution_context = self._pre_execution_violations(
            name, args
        )
        violations.extend(pre_violations)
        violations, governor = self._apply_sandbox_governor(
            execution_context, violations, commit_token_raw=commit_token_raw
        )
        action = self._action_descriptor(name, args)
        blocked = self._should_block(violations, action)
        if governor is not None and governor.is_blocking():
            blocked = True
        touched_resources = [f"mcp://{self.server_name}/{name}"]
        file_path = self._file_path_from_arguments(args)
        if file_path:
            touched_resources.append(f"file:{file_path}")

        if name not in self._async_handlers and name not in self._handlers:
            violations = [*violations, f"unregistered tool handler: {name}"]
            blocked = True

        if blocked:
            from agentauth.receipts.sandbox_governor import SandboxEnforcement

            outcome = (
                governor.decision_outcome()
                if governor is not None and governor.is_blocking()
                else DecisionOutcome.DENY
            )
            status = "blocked"
            if governor is not None and governor.enforcement == SandboxEnforcement.STEP_UP:
                status = "step_up_required"
            elif self._scope_step_up_requested(violations):
                status = "step_up_required"
            output = self._tool_output(name, status=status, violations=violations)
            auth_extras: dict[str, Any] = {}
            if monitoring_payload is not None:
                auth_extras["monitoring"] = monitoring_payload
            if isinstance(execution_context.authorization, dict):
                auth_extras.update(execution_context.authorization)
            execution_context.authorization = self._auth_context(
                name, args, blocked=True, authorization_extras=auth_extras
            )
            execution_context.touched_resources = touched_resources
            run = self.agent.record(
                action=action,
                context=execution_context,
                output=output,
                extra_violations=violations,
                check_policy_output=False,
                decision_outcome=outcome,
                session_id=self.session_id,
            )
            return ToolCallResult.from_run(name, args, run, blocked=True)

        from agentauth.capabilities.scoping.tools import commit_tool_call_budget

        commit_tool_call_budget(
            self._tool_call_budget,
            tool_name=name,
            arguments=args,
            side_effect=(
                self._tool_specs[name].side_effect_level
                if name in self._tool_specs
                else execution_context.action.side_effect_level
            ),
        )
        if self._value_budget is not None:
            self._value_budget.commit(name, args)

        if name in self._async_handlers:
            raw = await self._async_handlers[name](args)
        else:
            raw = self._handlers[name](args)

        output = self._tool_output(name, status="ok", result=raw)
        if isinstance(raw, dict):
            violations = [*violations, *self.agent.policy.check_output(raw)]

        auth_extras: dict[str, Any] = {}
        if isinstance(execution_context.authorization, dict):
            auth_extras.update(execution_context.authorization)
        run = self.agent.record(
            action=action,
            context={
                "input": args,
                "authorization": self._auth_context(
                    name, args, blocked=False, authorization_extras=auth_extras
                ),
                "touched_resources": touched_resources,
            },
            output=output,
            extra_violations=violations,
            session_id=self.session_id,
        )
        return ToolCallResult.from_run(name, args, run, blocked=False)
