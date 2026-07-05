"""Factory for building the full dynamic sandboxing stack.

``build_sandboxed_gateway()`` wires all components — scoping, monitors,
governors, and the MCP gateway — into a single ready-to-use system.

This eliminates the ~80 lines of setup code that was previously
duplicated across every test and the sandboxed MCP server.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.composite_monitor import CompositeMonitor
from agentauth.receipts.default_deny_governor import DefaultDenySandboxGovernor
from agentauth.receipts.drift_monitor import DriftScorer, DriftScorerConfig
from agentauth.receipts.novelty_monitor import NoveltyMonitor
from agentauth.receipts.instruction_surfaces import (
    is_agent_memory_path,
    is_instruction_surface_path,
)
from agentauth.receipts.protected_zone_governor import ProtectedZoneGovernor
from agentauth.core.runtime import SideEffectLevel
from agentauth.receipts.sandbox_governor import RuleBasedSandboxGovernor
from agentauth.receipts.scanning_monitor import ScanningScorer, ScanScorerConfig
from agentauth.receipts.tighten_policy import TighteningGovernor
from agentauth.receipts.mcp import ReceiptedMcpGateway
from agentauth.capabilities.scoping import build_capability_lease, build_repo_chunk_index
from agentauth.capabilities.scoping.capability_scope import apply_lease_to_authority
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.models import CapabilityLease, RepoChunkIndex
from agentauth.core.signing import generate_keypair


def build_protected_explicit_allow(
    goal: GoalSpec,
    lease: CapabilityLease,
) -> set[str]:
    """Refs that override protected-zone denial (instruction surfaces need explicit goal scope)."""
    pz_check = ProtectedZoneGovernor()
    explicit_allow: set[str] = set()
    for f in goal.explicit_allow_files():
        if is_agent_memory_path(f):
            if goal.allow_agent_memory_writes:
                explicit_allow.add(f"repo_write://{f}")
                explicit_allow.add(f"repo_read://{f}")
            continue
        if is_instruction_surface_path(f):
            explicit_allow.add(f"repo_write://{f}")
            explicit_allow.add(f"repo_read://{f}")
    for f in lease.write_files:
        wr = f"repo_write://{f}"
        rd = f"repo_read://{f}"
        if is_agent_memory_path(f):
            if goal.allow_agent_memory_writes and wr in explicit_allow:
                explicit_allow.add(wr)
                explicit_allow.add(rd)
            continue
        if is_instruction_surface_path(f):
            if wr not in explicit_allow:
                continue
        elif pz_check._is_protected(wr):
            continue
        explicit_allow.add(wr)
        explicit_allow.add(rd)
    for f in lease.read_files - lease.write_files:
        rd = f"repo_read://{f}"
        if is_agent_memory_path(f):
            if goal.allow_agent_memory_writes and rd in explicit_allow:
                explicit_allow.add(rd)
            continue
        if is_instruction_surface_path(f):
            if rd not in explicit_allow:
                continue
        elif pz_check._is_protected(rd):
            continue
        explicit_allow.add(rd)
    return explicit_allow


def build_sandboxed_gateway(
    repo_root: str | Path,
    goal: GoalSpec,
    *,
    tools: list[str] | None = None,
    read_tools: set[str] | None = None,
    commit_required_tools: set[str] | None = None,
    resource_ref_resolvers: dict[str, Any] | None = None,
    lease_ttl_seconds: int = 300,
    lease_call_budget: int = 50,
    mode: str = "bounded_auto",
    audit_db: str = ":memory:",
    auto_tighten_on_deny: bool = True,
    top_k: int = 8,
) -> tuple[ReceiptedMcpGateway, CapabilityLease, TighteningGovernor]:
    """Build the full dynamic sandboxing stack from a repo + goal.

    Returns ``(gateway, lease, tightening_governor)``.

    This wires:
    1. Repo index → capability lease (goal scoping)
    2. DriftScorer + ScanningScorer + NoveltyMonitor (composite monitor)
    3. ProtectedZoneGovernor → DefaultDenySandboxGovernor →
       TighteningGovernor → RuleBasedSandboxGovernor (governor chain)
    4. ReceiptedMcpGateway (broker enforcement)
    """
    root = Path(repo_root).resolve()

    # 1. Index + scope
    index = build_repo_chunk_index(root)
    lease = build_capability_lease(index, goal, top_k=top_k)

    # 2. Monitors
    scope_refs: set[str] = set()
    for f in lease.write_files:
        scope_refs.add(f"repo_write://{f}")
        scope_refs.add(f"repo_read://{f}")
    for f in lease.read_files - lease.write_files:
        scope_refs.add(f"repo_read://{f}")

    drift = DriftScorer(scope_refs, config=DriftScorerConfig(window=10, threshold=0.5))
    scan = ScanningScorer(config=ScanScorerConfig(window=15, max_unique_dirs=6, max_unique_files=20))
    novelty = NoveltyMonitor()
    for f in lease.read_files | lease.write_files:
        parts = f.replace("\\", "/").strip("/").split("/")
        if parts:
            novelty.approve_subsystem(parts[0])
    novelty.approve_tool_class("mcp.tools/call")
    composite = CompositeMonitor(drift=drift, scan=scan, novelty=novelty)

    # 3. Governor chain
    pk = generate_keypair()
    rules = RuleBasedSandboxGovernor(
        commit_required_tools=commit_required_tools or set(),
        permit_signing_key=pk,
        permit_ttl_seconds=60,
        lease_ttl_seconds=lease_ttl_seconds,
        lease_call_budget=lease_call_budget,
        require_active_lease=True,
        honor_monitor_recommendations=True,
        suspend_lease_renewal_on_suspicion=True,
    )
    tightening = TighteningGovernor(inner=rules, auto_tighten_on_deny=auto_tighten_on_deny)
    default_deny = DefaultDenySandboxGovernor(inner=tightening)

    explicit_allow = build_protected_explicit_allow(goal, lease)
    protected = ProtectedZoneGovernor(
        inner=default_deny,
        explicit_allow=explicit_allow,
        allow_agent_memory_writes=goal.allow_agent_memory_writes,
    )

    # 4. Agent + Gateway
    tool_names = tools or [
        "read_file", "write_file", "list_dir", "grep_repo",
        "run_shell", "run_tests",
    ]
    policy = Policy.from_dict({
        "version": 1,
        "name": "sandboxed",
        "tier": "structural",
        "capability": "fully_proven",
        "allowed_tools": {"tools": tool_names},
    })
    cert = dev_certificate(policy.commitment(), scope=tool_names)
    agent = AgentWrapper(
        model=lambda inp: {},
        policy=policy,
        certificate=cert,
        mode=mode,
        audit_db=audit_db,
    )

    ck = generate_keypair()
    gw = ReceiptedMcpGateway(
        agent,
        server_name="sandboxed",
        sandbox_governor=protected,
        behavior_monitor=composite,
        query_id=goal.query_id,
        commit_signing_key=ck,
        commit_ttl_seconds=300,
        authority_id="sandboxed",
    )

    # 5. Resource ref resolvers
    default_resolvers = {
        "read_file": lambda a: f"repo_read://{a.get('path', '')}" if a.get("path") else None,
        "write_file": lambda a: f"repo_write://{a.get('path', '')}" if a.get("path") else None,
        "list_dir": lambda a: f"repo_read://{a.get('path', '.')}",
        "grep_repo": lambda a: f"repo_read://{a.get('path', '.')}",
        "run_shell": lambda a: f"repo_write://{a.get('cwd', '.')}",
        "run_tests": lambda a: f"repo_read://{a.get('path', 'tests')}",
    }
    if resource_ref_resolvers:
        default_resolvers.update(resource_ref_resolvers)
    for name, resolver in default_resolvers.items():
        gw._resource_ref_resolvers[name] = resolver

    # 6. Side-effect levels
    _read_tools = read_tools or {"read_file", "list_dir", "grep_repo", "run_tests"}
    _orig = gw._action_descriptor

    def _patched(tool_name: str, arguments: dict | None = None):
        ad = _orig(tool_name, arguments)
        if tool_name in _read_tools:
            ad.side_effect_level = SideEffectLevel.READ_ONLY
        return ad

    gw._action_descriptor = _patched

    # 7. Register stub handlers (tests replace these)
    for name in tool_names:
        gw.register_tool(name, lambda args: {"ok": True})

    # 8. Seed authority with lease + gateway enforcement state
    gw._capability_lease = lease
    auth = gw.authority()
    apply_lease_to_authority(auth, lease)
    scope: list[str] = []
    for f in lease.write_files:
        scope.append(f"repo_write://{f}")
        scope.append(f"repo_read://{f}")
    for f in lease.read_files - lease.write_files:
        scope.append(f"repo_read://{f}")
    auth.resource_scope = sorted(set(scope))
    auth.expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    auth.lease_remaining_calls = lease_call_budget
    gw.set_authority(auth)

    return gw, lease, tightening
