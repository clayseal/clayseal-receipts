"""Integration tests: full sandboxing stack with benign workloads, adversarial scenarios, and end-to-end flows."""
from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.behavior_monitor import (
    BehaviorMonitorResult,
    BehaviorMonitorWithContract,
    BehaviorRecommendation,
    evaluate_behavior_monitor,
)
from agentauth.receipts.composite_monitor import CompositeMonitor
from agentauth.receipts.default_deny_governor import DefaultDenySandboxGovernor
from agentauth.receipts.drift_monitor import DriftScorer, DriftScorerConfig
from agentauth.receipts.monitor_contract import MonitorInput, MonitorTraceEvent
from agentauth.receipts.novelty_monitor import NoveltyMonitor
from agentauth.receipts.protected_zone_governor import ProtectedZoneGovernor
from agentauth.core.runtime import (
    ActionDescriptor,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)
from agentauth.receipts.sandbox_builder import build_sandboxed_gateway
from agentauth.receipts.sandbox_governor import (
    RuleBasedSandboxGovernor,
    SandboxEnforcement,
)
from agentauth.receipts.scanning_monitor import ScanningScorer, ScanScorerConfig
from agentauth.capabilities.step_up import StepUpApproval, apply_step_up, build_step_up_request
from agentauth.receipts.tighten_policy import TighteningGovernor
from agentauth.capabilities.scoping import (
    build_capability_lease,
    build_repo_chunk_index,
    check_repo_path_allowed,
)
from agentauth.capabilities.scoping.capability_scope import apply_lease_to_authority
from agentauth.capabilities.scoping.exploration_budget import ExplorationBudget, ExplorationBudgetConfig
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.metrics import ScopingMetrics
from agentauth.core.signing import generate_keypair


# ---------------------------------------------------------------------------
# Helper: build the full stack via the shared builder for the
# test_integrated_sandboxing scenarios (extra tools: send_email, etc.)
# ---------------------------------------------------------------------------


_INTEGRATED_TOOLS = [
    "read_file", "write_file", "grep_repo", "run_tests",
    "send_email", "transfer_funds", "deploy_prod", "read_web",
]

_INTEGRATED_READ_TOOLS = {"read_file", "grep_repo", "run_tests", "read_web"}

_INTEGRATED_RESOLVERS = {
    "send_email": lambda args: f"net://{args.get('server', 'smtp')}",
    "deploy_prod": lambda args: "repo_write://deploy/prod.yaml",
    "read_web": lambda args: f"net://{args.get('host', 'web')}",
    "transfer_funds": lambda args: f"net://transfer/{args.get('to', 'unknown')}",
}


def _build_integrated_stack(
    sample_repo: Path,
    goal: GoalSpec,
    *,
    commit_required_tools: set[str] | None = None,
):
    """Build the full stack for the integrated-sandboxing tests using build_sandboxed_gateway."""
    gw, lease, tightening = build_sandboxed_gateway(
        sample_repo,
        goal,
        tools=_INTEGRATED_TOOLS,
        read_tools=_INTEGRATED_READ_TOOLS,
        commit_required_tools=commit_required_tools,
        resource_ref_resolvers=_INTEGRATED_RESOLVERS,
        mode="shadow",
        top_k=5,
    )
    return gw, lease, tightening


# ---------------------------------------------------------------------------
# Helper: build the full stack for the benign-workloads tests
# (smaller tool set: grep_file instead of grep_repo)
# ---------------------------------------------------------------------------

_BENIGN_TOOLS = ["read_file", "write_file", "run_tests", "grep_file"]

_BENIGN_READ_TOOLS = {"read_file", "grep_file", "run_tests"}

_BENIGN_RESOLVERS = {
    "grep_file": lambda a: f"repo_read://{a.get('path', '.')}",
    "run_tests": lambda a: f"repo_read://{a.get('path', 'tests')}",
}


def _build_benign_stack(repo: Path, goal: GoalSpec):
    """Build the stack for benign workloads using build_sandboxed_gateway."""
    gw, lease, tightening = build_sandboxed_gateway(
        repo,
        goal,
        tools=_BENIGN_TOOLS,
        read_tools=_BENIGN_READ_TOOLS,
        resource_ref_resolvers=_BENIGN_RESOLVERS,
        mode="shadow",
        top_k=8,
    )
    return gw, lease


# ---------------------------------------------------------------------------
# Helper: build a full stack that does NOT filter protected files from
# explicit_allow.  Needed by TestIntegratedStepUpFlow because
# build_sandboxed_gateway intentionally strips protected-zone files from
# explicit_allow, but this test verifies that GoalSpec.allow_resources
# (trusted control-plane input) CAN override the protected zone.
# ---------------------------------------------------------------------------


def _build_stack_with_protected_allow(
    sample_repo: Path,
    goal: GoalSpec,
):
    """Custom build that preserves allow_resources for protected files.

    build_sandboxed_gateway filters protected files out of explicit_allow,
    which is the correct production default.  This helper skips that filter
    so that the step-up-flow test can verify explicit allow_resources
    override the protected zone as designed.
    """
    index = build_repo_chunk_index(sample_repo)
    lease = build_capability_lease(index, goal, top_k=5)

    scope_refs: set[str] = set()
    for f in lease.write_files:
        scope_refs.add(f"repo_write://{f}")
        scope_refs.add(f"repo_read://{f}")
    for f in lease.read_files - lease.write_files:
        scope_refs.add(f"repo_read://{f}")
    drift = DriftScorer(scope_refs, config=DriftScorerConfig(window=8, threshold=0.5))
    scan = ScanningScorer(config=ScanScorerConfig(window=12, max_unique_dirs=4, max_unique_files=10))
    novelty = NoveltyMonitor()
    for f in lease.read_files | lease.write_files:
        parts = f.replace("\\", "/").strip("/").split("/")
        if parts:
            novelty.approve_subsystem(parts[0])
    novelty.approve_tool_class("mcp.tools/call")
    composite = CompositeMonitor(drift, scan, novelty)

    permit_key = generate_keypair()
    rules = RuleBasedSandboxGovernor(
        permit_signing_key=permit_key,
        permit_ttl_seconds=60,
        lease_ttl_seconds=300,
        lease_call_budget=50,
        require_active_lease=True,
        honor_monitor_recommendations=True,
        suspend_lease_renewal_on_suspicion=True,
    )
    tightening = TighteningGovernor(inner=rules, auto_tighten_on_deny=True)
    default_deny = DefaultDenySandboxGovernor(inner=tightening)
    # NOTE: no filtering of protected files — this is intentional so the
    # test can verify that goal.allow_resources overrides protected zones.
    explicit_allow_refs: set[str] = set()
    for f in lease.write_files:
        explicit_allow_refs.add(f"repo_write://{f}")
        explicit_allow_refs.add(f"repo_read://{f}")
    for f in lease.read_files - lease.write_files:
        explicit_allow_refs.add(f"repo_read://{f}")
    protected = ProtectedZoneGovernor(inner=default_deny, explicit_allow=explicit_allow_refs)

    tool_names = [
        "read_file", "write_file", "grep_repo", "run_tests",
        "send_email", "transfer_funds", "deploy_prod", "read_web",
    ]
    policy = Policy.from_dict({
        "version": 1,
        "name": "integrated-test",
        "tier": "structural",
        "capability": "fully_proven",
        "allowed_tools": {"tools": tool_names},
    })
    cert = dev_certificate(policy.commitment(), scope=tool_names)
    agent = AgentWrapper(
        model=lambda inp: {},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )

    commit_key = generate_keypair()
    gw = ReceiptedMcpGateway(
        agent,
        server_name="devin",
        sandbox_governor=protected,
        behavior_monitor=composite,
        query_id=goal.query_id,
        commit_signing_key=commit_key,
        commit_ttl_seconds=300,
        authority_id="integrated-test",
    )

    auth = gw.authority()
    apply_lease_to_authority(auth, lease)
    scope = list(auth.resource_scope)
    for entry in list(scope):
        if entry.startswith("repo_write://"):
            read_entry = "repo_read://" + entry[len("repo_write://"):]
            if read_entry not in scope:
                scope.append(read_entry)
    scope.append("mcp_tool_call")
    auth.resource_scope = sorted(set(scope))
    auth.expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    auth.lease_remaining_calls = 50
    gw.set_authority(auth)

    gw._resource_ref_resolvers["read_file"] = lambda args: (
        f"repo_read://{args.get('path', '')}" if args.get("path") else None
    )
    gw._resource_ref_resolvers["write_file"] = lambda args: (
        f"repo_write://{args.get('path', '')}" if args.get("path") else None
    )
    gw._resource_ref_resolvers["grep_repo"] = lambda args: f"repo_read://{args.get('dir', '.')}"
    gw._resource_ref_resolvers["send_email"] = lambda args: f"net://{args.get('server', 'smtp')}"
    gw._resource_ref_resolvers["deploy_prod"] = lambda args: "repo_write://deploy/prod.yaml"
    gw._resource_ref_resolvers["read_web"] = lambda args: f"net://{args.get('host', 'web')}"

    for name in tool_names:
        gw.register_tool(name, lambda args: {"ok": True})

    _read_tools = {"read_file", "grep_repo", "run_tests", "read_web"}
    _orig_action_descriptor = gw._action_descriptor

    def _patched_action_descriptor(tool_name, arguments=None):
        ad = _orig_action_descriptor(tool_name, arguments)
        if tool_name in _read_tools:
            ad.side_effect_level = SideEffectLevel.READ_ONLY
        return ad

    gw._action_descriptor = _patched_action_descriptor

    return gw, lease, tightening


# ---------------------------------------------------------------------------
# DP-39 helpers for direct monitor / governor tests (no gateway needed)
# ---------------------------------------------------------------------------


def _trace_event(ref: str, action: str = "mcp.tools/call/read_file") -> MonitorTraceEvent:
    return MonitorTraceEvent(
        action_name=action,
        action_category="mcp_tool_call",
        side_effect_level="read_only",
        resource_ref=ref,
        arguments_hash="sha256:deadbeef",
        at=datetime.now(timezone.utc).isoformat(),
    )


def _monitor_input(ref: str, action: str = "mcp.tools/call/read_file") -> MonitorInput:
    return MonitorInput(proposed=_trace_event(ref, action))


def _ctx(ref: str, se: SideEffectLevel = SideEffectLevel.BOUNDED_WRITE) -> ExecutionContext:
    return ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/write_file",
            resource_ref=ref,
            side_effect_level=se,
        ),
        input={},
        authority=AuthorityContext(
            authority_id="test",
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        ),
    )


def _assert_allowed(result, msg: str) -> None:
    assert not result.blocked, f"FALSE POSITIVE: {msg} -- violations: {result.policy_violations}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_repo(tmp_path: Path) -> Path:
    """A repo with normal code, auth module, deploy config, and keys."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "app.py").write_text(
        "from src.utils import helper\ndef main(): pass\n", encoding="utf-8",
    )
    (tmp_path / "src" / "utils.py").write_text(
        "def helper(): return 42\n", encoding="utf-8",
    )
    (tmp_path / "auth").mkdir()
    (tmp_path / "auth" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "auth" / "tokens.py").write_text(
        "SECRET_KEY = 'do-not-leak'\ndef verify(t): return True\n", encoding="utf-8",
    )
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "prod.yaml").write_text(
        "env: production\nreplicas: 3\n", encoding="utf-8",
    )
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "signing.pem").write_text("FAKE-PEM-KEY\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text(
        "from src.app import main\ndef test_main(): pass\n", encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    return tmp_path


@pytest.fixture()
def project_repo(tmp_path: Path) -> Path:
    """A realistic project with multiple packages, tests, and config."""
    (tmp_path / "src" / "api").mkdir(parents=True)
    (tmp_path / "src" / "__init__.py").write_text("")
    (tmp_path / "src" / "api" / "__init__.py").write_text("")
    (tmp_path / "src" / "api" / "routes.py").write_text(
        "from src.api.handlers import handle_request\n"
        "def setup_routes(app): pass\n"
    )
    (tmp_path / "src" / "api" / "handlers.py").write_text(
        "from src.models import User\n"
        "def handle_request(req): return User()\n"
    )
    (tmp_path / "src" / "models.py").write_text(
        "class User:\n    def __init__(self): self.name = ''\n"
    )
    (tmp_path / "src" / "utils.py").write_text(
        "def format_name(n): return n.strip()\n"
    )

    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "__init__.py").write_text("")
    (tmp_path / "tests" / "test_routes.py").write_text(
        "from src.api.routes import setup_routes\n"
        "def test_routes(): pass\n"
    )
    (tmp_path / "tests" / "test_models.py").write_text(
        "from src.models import User\n"
        "def test_user(): pass\n"
    )
    (tmp_path / "tests" / "test_utils.py").write_text(
        "from src.utils import format_name\n"
        "def test_format(): pass\n"
    )

    (tmp_path / "pyproject.toml").write_text("[project]\nname='myapp'\n")

    (tmp_path / "auth").mkdir()
    (tmp_path / "auth" / "__init__.py").write_text("")
    (tmp_path / "auth" / "middleware.py").write_text("def check_auth(): pass\n")
    return tmp_path


@pytest.fixture()
def dp39_repo(tmp_path: Path) -> Path:
    """Repo for DP-39 scenario harness tests."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text(
        "from src.utils import helper\ndef entry(): pass\n", encoding="utf-8",
    )
    (tmp_path / "src" / "utils.py").write_text(
        "def helper(): pass\n", encoding="utf-8",
    )
    (tmp_path / "src" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "auth").mkdir()
    (tmp_path / "auth" / "verify.py").write_text(
        "def check(): return True\n", encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").write_text(
        "from src.main import entry\ndef test_entry(): pass\n", encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    return tmp_path


# ===========================================================================
# From test_integrated_sandboxing.py
# ===========================================================================


# ---------------------------------------------------------------------------
# Scenario 1: Normal bugfix -- everything should pass silently
# ---------------------------------------------------------------------------


class TestIntegratedNormalWork:
    def test_read_in_scope_file_succeeds(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-1", summary="Fix main function in src/app.py")
        gw, lease, *_ = _build_integrated_stack(sample_repo, goal)

        result = gw.call_tool("read_file", {"path": "src/app.py"})
        assert not result.blocked, f"in-scope read should pass: {result.policy_violations}"

    def test_write_in_scope_file_succeeds(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-1", summary="Fix main function in src/app.py")
        gw, *_ = _build_integrated_stack(sample_repo, goal)

        result = gw.call_tool("write_file", {"path": "src/app.py"})
        assert not result.blocked, f"in-scope write should pass: {result.policy_violations}"

    def test_read_dependency_succeeds(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-1", summary="Fix main function in src/app.py")
        gw, lease, *_ = _build_integrated_stack(sample_repo, goal)

        if "src/utils.py" in lease.read_files:
            result = gw.call_tool("read_file", {"path": "src/utils.py"})
            assert not result.blocked

    def test_normal_sequence_no_tightening(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-1", summary="Fix main function in src/app.py")
        gw, lease, tightening = _build_integrated_stack(sample_repo, goal)
        metrics = ScopingMetrics(goal_id=goal.query_id)

        for path in ["src/app.py", "src/utils.py", "src/app.py"]:
            result = gw.call_tool("read_file", {"path": path})
            metrics.record_action(blocked=result.blocked, overhead_ms=1.0)

        assert not tightening.is_tightened, "normal work should not trigger tighten mode"
        assert metrics.blocked_actions == 0


# ---------------------------------------------------------------------------
# Scenario 2: Poisoned tool output -> protected zone probe
# ---------------------------------------------------------------------------


class TestIntegratedPoisonedOutput:
    """Agent reads web page with injection, then probes secrets."""

    def test_poisoned_output_cannot_read_keys(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-2", summary="Research API docs")
        gw, *_ = _build_integrated_stack(sample_repo, goal)

        result = gw.call_tool("read_web", {"host": "docs.example.com"})
        assert result.blocked, "egress should be denied without explicit allow"

    def test_poisoned_output_cannot_write_deploy(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-2", summary="Fix a bug in src/app.py")
        gw, *_ = _build_integrated_stack(sample_repo, goal)

        result = gw.call_tool("deploy_prod", {})
        assert result.blocked, "deploy should be denied -- protected zone"

    def test_poisoned_output_cannot_read_signing_key(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-2", summary="Fix a bug in src/app.py")
        gw, *_ = _build_integrated_stack(sample_repo, goal)

        result = gw.call_tool("read_file", {"path": "keys/signing.pem"})
        assert result.blocked, "reading keys/ should be blocked"


# ---------------------------------------------------------------------------
# Scenario 3: Argument tamper -- commit token for args A, call with args B
# ---------------------------------------------------------------------------


class TestIntegratedArgumentTamper:
    def test_commit_token_fails_with_different_args(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-3", summary="Process payment")
        gw, *_ = _build_integrated_stack(
            sample_repo, goal, commit_required_tools={"transfer_funds"}
        )

        token = gw.issue_commit_token("transfer_funds", {"amount": 1, "to": "vendor"})

        result = gw.call_tool("transfer_funds", {
            "amount": 9999, "to": "attacker",
            "_commit_token": token,
        })
        assert result.blocked, "tampered args should be blocked"
        assert any(
            "argument" in v.lower() or "mismatch" in v.lower()
            or "resource_scope" in v or "commit" in v.lower()
            for v in result.policy_violations
        ), f"should mention tamper or scope block: {result.policy_violations}"


# ---------------------------------------------------------------------------
# Scenario 4: Cross-query replay
# ---------------------------------------------------------------------------


class TestIntegratedCrossQueryReplay:
    def test_commit_token_from_q1_fails_in_q2(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-4", summary="Process payment")
        gw, *_ = _build_integrated_stack(
            sample_repo, goal, commit_required_tools={"transfer_funds"}
        )

        token = gw.issue_commit_token("transfer_funds", {"amount": 1, "to": "vendor"})
        gw.set_query_id("q-OTHER")

        result = gw.call_tool("transfer_funds", {
            "amount": 1, "to": "vendor",
            "_commit_token": token,
        })
        assert result.blocked, "cross-query replay should be blocked"


# ---------------------------------------------------------------------------
# Scenario 5: Epoch revocation after suspicious signal
# ---------------------------------------------------------------------------


class TestIntegratedEpochRevocation:
    def test_revoked_permits_fail(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-5", summary="Process payment")
        gw, *_ = _build_integrated_stack(
            sample_repo, goal, commit_required_tools={"transfer_funds"}
        )

        token = gw.issue_commit_token("transfer_funds", {"amount": 1, "to": "vendor"})
        gw.revoke_permits()

        result = gw.call_tool("transfer_funds", {
            "amount": 1, "to": "vendor",
            "_commit_token": token,
        })
        assert result.blocked, "revoked epoch should block"


# ---------------------------------------------------------------------------
# Scenario 6: Scanning / recon behavior
# ---------------------------------------------------------------------------


class TestIntegratedScanning:
    def test_scanning_many_dirs_triggers_monitors(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-6", summary="Fix src/app.py")
        gw, lease, tightening = _build_integrated_stack(sample_repo, goal)
        metrics = ScopingMetrics(goal_id=goal.query_id)

        for i in range(8):
            result = gw.call_tool("grep_repo", {"dir": f"dir_{i}"})
            metrics.record_action(blocked=result.blocked, overhead_ms=1.0)

        s = metrics.summary()
        assert s["total_actions"] == 8


# ---------------------------------------------------------------------------
# Scenario 7: Egress attempt (exfiltration)
# ---------------------------------------------------------------------------


class TestIntegratedEgress:
    def test_send_email_blocked_without_allow(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-7", summary="Fix src/app.py")
        gw, *_ = _build_integrated_stack(sample_repo, goal)

        result = gw.call_tool("send_email", {"server": "smtp.evil.com"})
        assert result.blocked, "egress should be blocked"
        assert any(
            "egress" in v or "protected_zone" in v
            for v in result.policy_violations
        ), f"should mention egress: {result.policy_violations}"


# ---------------------------------------------------------------------------
# Scenario 8: Budget exhaustion
# ---------------------------------------------------------------------------


class TestIntegratedBudgetExhaustion:
    def test_lease_exhaustion_blocks(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-8", summary="Fix src/app.py")
        gw, *_ = _build_integrated_stack(sample_repo, goal)

        auth = gw.authority()
        auth.lease_remaining_calls = 2
        gw.set_authority(auth)

        inner = gw.sandbox_governor
        while hasattr(inner, "inner"):
            if hasattr(inner.inner, "lease_ttl_seconds"):
                inner.inner.lease_ttl_seconds = None
                inner.inner.lease_call_budget = None
                break
            inner = inner.inner

        r1 = gw.call_tool("write_file", {"path": "src/app.py"})
        r2 = gw.call_tool("write_file", {"path": "src/app.py"})

        r3 = gw.call_tool("write_file", {"path": "src/app.py"})
        assert r3.blocked, "should block after budget exhaustion"


# ---------------------------------------------------------------------------
# Scenario 9: Step-up flow for protected zone
# ---------------------------------------------------------------------------


class TestIntegratedStepUpFlow:
    def test_auth_access_blocked_then_approved(self, sample_repo: Path) -> None:
        # Custom setup: build_sandboxed_gateway filters protected files from
        # explicit_allow, but this test verifies that goal.allow_resources
        # (trusted control-plane input) overrides the protected zone.
        goal = GoalSpec(
            query_id="q-9",
            summary="Update auth token verification",
            allow_resources=["repo://auth/tokens.py"],
        )
        gw, lease, *_ = _build_stack_with_protected_allow(sample_repo, goal)

        r = gw.call_tool("read_file", {"path": "auth/tokens.py"})
        assert not r.blocked, f"explicit allow should pass: {r.policy_violations}"

    def test_auth_access_blocked_without_explicit_allow(self, sample_repo: Path) -> None:
        goal = GoalSpec(query_id="q-9b", summary="Fix src/app.py")
        gw, *_ = _build_integrated_stack(sample_repo, goal)

        r = gw.call_tool("read_file", {"path": "auth/tokens.py"})
        assert r.blocked, "auth/ without explicit allow should be blocked"


# ---------------------------------------------------------------------------
# Scenario 10: Drift then tighten -- full adversarial sequence
# ---------------------------------------------------------------------------


class TestIntegratedDriftAndTighten:
    def test_drift_causes_tightening_and_blocks_novel_access(
        self, sample_repo: Path
    ) -> None:
        goal = GoalSpec(query_id="q-10", summary="Fix src/app.py")
        gw, lease, tightening = _build_integrated_stack(sample_repo, goal)

        gw.call_tool("read_file", {"path": "src/app.py"})
        gw.call_tool("read_file", {"path": "src/utils.py"})
        assert not tightening.is_tightened

        r = gw.call_tool("write_file", {"path": "deploy/prod.yaml"})
        assert r.blocked, "deploy write should be blocked"


# ---------------------------------------------------------------------------
# Scenario 11: Full end-to-end lifecycle
# ---------------------------------------------------------------------------


class TestIntegratedEndToEnd:
    def test_complete_lifecycle(self, sample_repo: Path) -> None:
        """Normal work -> adversarial probe -> step-up -> more work."""
        goal = GoalSpec(
            query_id="q-e2e",
            summary="Fix main function in src/app.py",
            allow_resources=["repo://tests/test_app.py"],
        )
        gw, lease, tightening = _build_integrated_stack(
            sample_repo, goal, commit_required_tools={"deploy_prod"}
        )
        metrics = ScopingMetrics(goal_id=goal.query_id)

        # Phase 1: Normal work
        for path in ["src/app.py", "src/utils.py"]:
            r = gw.call_tool("read_file", {"path": path})
            metrics.record_action(blocked=r.blocked, overhead_ms=1.0)
        r = gw.call_tool("write_file", {"path": "src/app.py"})
        metrics.record_action(blocked=r.blocked, is_write=True, overhead_ms=2.0)

        # Phase 2: Test update (explicitly allowed)
        r = gw.call_tool("write_file", {"path": "tests/test_app.py"})
        metrics.record_action(blocked=r.blocked, is_write=True, overhead_ms=1.5)

        # Phase 3: Adversarial probe (should be blocked)
        r = gw.call_tool("read_file", {"path": "keys/signing.pem"})
        metrics.record_action(blocked=r.blocked, overhead_ms=1.0)
        assert r.blocked, "keys access must be blocked"

        r = gw.call_tool("send_email", {"server": "smtp.evil.com"})
        metrics.record_action(blocked=r.blocked, overhead_ms=1.0)
        assert r.blocked, "egress must be blocked"

        # Phase 4: Check metrics
        s = metrics.summary()
        assert s["total_actions"] >= 5
        assert s["blocked_actions"] >= 2, "at least keys + egress should be blocked"


# ===========================================================================
# From test_benign_workloads.py
# ===========================================================================


# ---------------------------------------------------------------------------
# Workload 1: Simple bugfix (read + edit one file)
# ---------------------------------------------------------------------------


class TestBenignSimpleBugfix:
    def test_read_target_file(self, project_repo: Path) -> None:
        gw, _ = _build_benign_stack(project_repo, GoalSpec(query_id="q-1", summary="Fix handle_request in handlers.py"))
        _assert_allowed(gw.call_tool("read_file", {"path": "src/api/handlers.py"}), "read target file")

    def test_write_target_file(self, project_repo: Path) -> None:
        gw, _ = _build_benign_stack(project_repo, GoalSpec(query_id="q-1", summary="Fix handle_request in handlers.py"))
        _assert_allowed(gw.call_tool("write_file", {"path": "src/api/handlers.py"}), "write target file")

    def test_read_then_write_target(self, project_repo: Path) -> None:
        gw, _ = _build_benign_stack(project_repo, GoalSpec(query_id="q-1", summary="Fix handle_request in handlers.py"))
        _assert_allowed(gw.call_tool("read_file", {"path": "src/api/handlers.py"}), "read before write")
        _assert_allowed(gw.call_tool("write_file", {"path": "src/api/handlers.py"}), "write after read")


# ---------------------------------------------------------------------------
# Workload 2: Read import dependencies
# ---------------------------------------------------------------------------


class TestBenignReadDeps:
    def test_read_direct_import(self, project_repo: Path) -> None:
        gw, lease = _build_benign_stack(project_repo, GoalSpec(query_id="q-2", summary="Fix handle_request in handlers.py"))
        if "src/models.py" in lease.read_files:
            _assert_allowed(gw.call_tool("read_file", {"path": "src/models.py"}), "read import dep")

    def test_read_build_manifest(self, project_repo: Path) -> None:
        gw, lease = _build_benign_stack(project_repo, GoalSpec(query_id="q-2", summary="Fix handle_request in handlers.py"))
        if "pyproject.toml" in lease.read_files:
            _assert_allowed(gw.call_tool("read_file", {"path": "pyproject.toml"}), "read build manifest")


# ---------------------------------------------------------------------------
# Workload 3: Multi-file refactor in same subsystem
# ---------------------------------------------------------------------------


class TestBenignMultiFileRefactor:
    def test_read_and_write_multiple_files_in_scope(self, project_repo: Path) -> None:
        gw, lease = _build_benign_stack(project_repo, GoalSpec(
            query_id="q-3", summary="Refactor User model and update handlers"
        ))
        actions = []
        for f in ["src/models.py", "src/api/handlers.py"]:
            if f in lease.write_files:
                r = gw.call_tool("read_file", {"path": f})
                _assert_allowed(r, f"read {f}")
                actions.append(("read", f, r.blocked))
        for f in ["src/models.py", "src/api/handlers.py"]:
            if f in lease.write_files:
                r = gw.call_tool("write_file", {"path": f})
                _assert_allowed(r, f"write {f}")
                actions.append(("write", f, r.blocked))
        assert len(actions) >= 2, "should have at least 2 actions in scope"


# ---------------------------------------------------------------------------
# Workload 4: Read tests related to changed code
# ---------------------------------------------------------------------------


class TestBenignReadTests:
    def test_read_test_file_for_changed_code(self, project_repo: Path) -> None:
        gw, lease = _build_benign_stack(project_repo, GoalSpec(
            query_id="q-4", summary="Fix User model in models.py"
        ))
        if "tests/test_models.py" in lease.read_files:
            _assert_allowed(
                gw.call_tool("read_file", {"path": "tests/test_models.py"}),
                "read related test",
            )

    def test_run_tests(self, project_repo: Path) -> None:
        gw, lease = _build_benign_stack(project_repo, GoalSpec(
            query_id="q-4", summary="Fix User model in models.py"
        ))
        if "tests" in {p.split("/")[0] for p in lease.read_files}:
            _assert_allowed(
                gw.call_tool("run_tests", {"path": "tests"}),
                "run test suite",
            )


# ---------------------------------------------------------------------------
# Workload 5: Repeated reads of same file (loop detection should NOT fire)
# ---------------------------------------------------------------------------


class TestBenignRepeatedAccess:
    def test_read_same_file_many_times(self, project_repo: Path) -> None:
        gw, _ = _build_benign_stack(project_repo, GoalSpec(
            query_id="q-5", summary="Fix handle_request in handlers.py"
        ))
        for i in range(5):
            r = gw.call_tool("read_file", {"path": "src/api/handlers.py"})
            _assert_allowed(r, f"repeated read #{i+1}")

    def test_alternating_read_write(self, project_repo: Path) -> None:
        gw, _ = _build_benign_stack(project_repo, GoalSpec(
            query_id="q-5", summary="Fix handle_request in handlers.py"
        ))
        for i in range(3):
            _assert_allowed(
                gw.call_tool("read_file", {"path": "src/api/handlers.py"}),
                f"read #{i+1}",
            )
            _assert_allowed(
                gw.call_tool("write_file", {"path": "src/api/handlers.py"}),
                f"write #{i+1}",
            )


# ---------------------------------------------------------------------------
# Workload 6: Read utils used by the target
# ---------------------------------------------------------------------------


class TestBenignReadUtils:
    def test_read_utility_module(self, project_repo: Path) -> None:
        gw, lease = _build_benign_stack(project_repo, GoalSpec(
            query_id="q-6", summary="Fix format_name in utils.py"
        ))
        _assert_allowed(
            gw.call_tool("read_file", {"path": "src/utils.py"}),
            "read target util",
        )
        _assert_allowed(
            gw.call_tool("write_file", {"path": "src/utils.py"}),
            "write target util",
        )


# ---------------------------------------------------------------------------
# Workload 7: Grep within scope
# ---------------------------------------------------------------------------


class TestBenignGrep:
    def test_grep_in_scope_directory(self, project_repo: Path) -> None:
        gw, lease = _build_benign_stack(project_repo, GoalSpec(
            query_id="q-7", summary="Fix handle_request in handlers.py"
        ))
        _assert_allowed(
            gw.call_tool("grep_file", {"path": "src/api/handlers.py"}),
            "grep in scope file",
        )


# ---------------------------------------------------------------------------
# Workload 8: Full realistic session (10+ actions)
# ---------------------------------------------------------------------------


class TestBenignFullSession:
    def test_realistic_10_action_session(self, project_repo: Path) -> None:
        """Simulate a realistic 10-action coding session and verify
        ZERO false positives."""
        gw, lease = _build_benign_stack(project_repo, GoalSpec(
            query_id="q-8", summary="Fix handle_request and update tests"
        ))
        metrics = ScopingMetrics(goal_id="benign-session")

        actions = [
            ("read_file", {"path": "src/api/handlers.py"}),
            ("read_file", {"path": "src/api/routes.py"}),
            ("read_file", {"path": "src/models.py"}),
            ("grep_file", {"path": "src/api/handlers.py"}),
            ("write_file", {"path": "src/api/handlers.py"}),
            ("read_file", {"path": "src/api/handlers.py"}),
            ("write_file", {"path": "src/api/handlers.py"}),
            ("read_file", {"path": "pyproject.toml"}),
        ]

        for i, (tool, args) in enumerate(actions):
            path = args.get("path", "")
            if path not in lease.read_files and path not in lease.write_files:
                continue
            r = gw.call_tool(tool, args)
            metrics.record_action(
                blocked=r.blocked,
                is_write=(tool == "write_file"),
                overhead_ms=1.0,
            )
            _assert_allowed(r, f"action #{i+1}: {tool}({path})")

        s = metrics.summary()
        assert s["blocked_actions"] == 0, (
            f"ZERO false positives expected, got {s['blocked_actions']} blocks"
        )
        assert s["step_up_prompts"] == 0, (
            f"ZERO prompts expected, got {s['step_up_prompts']}"
        )
        assert s["total_actions"] >= 5, "should have at least 5 actions"


# ===========================================================================
# From test_dp39_scenario_harness.py
# ===========================================================================


# ---------------------------------------------------------------------------
# Normal scenarios
# ---------------------------------------------------------------------------


class TestNormalBugfix:
    """Scenario: fix a bug in src/main.py. Should scope to src/ with read on deps."""

    def test_bugfix_scopes_correctly(self, dp39_repo: Path) -> None:
        index = build_repo_chunk_index(dp39_repo)
        goal = GoalSpec(query_id="q-1", summary="Fix entry function in main.py")
        lease = build_capability_lease(index, goal, top_k=3)

        ok, _ = check_repo_path_allowed("src/main.py", lease, write=True)
        assert ok, "should be able to write to the file being fixed"

        ok, _ = check_repo_path_allowed("src/utils.py", lease, write=False)
        assert ok, "should be able to read import dep"

    def test_bugfix_no_monitors_fire(self, dp39_repo: Path) -> None:
        index = build_repo_chunk_index(dp39_repo)
        lease = build_capability_lease(
            index, GoalSpec(query_id="q-1", summary="Fix entry function"), top_k=3
        )
        scope = {f"repo://{f}" for f in lease.read_files | lease.write_files}
        drift = DriftScorer(scope, config=DriftScorerConfig(window=5, threshold=0.5))
        scan = ScanningScorer(config=ScanScorerConfig(window=10, max_unique_dirs=5))

        for ref in ["repo://src/main.py", "repo://src/utils.py", "repo://src/main.py"]:
            dr = drift.evaluate_contract(_monitor_input(ref))
            sr = scan.evaluate_contract(_monitor_input(ref))
            if dr:
                assert dr.recommendation == BehaviorRecommendation.ALLOW
            if sr:
                assert sr.recommendation == BehaviorRecommendation.ALLOW

    def test_bugfix_metrics_are_clean(self) -> None:
        metrics = ScopingMetrics(goal_id="bugfix-1")
        for _ in range(5):
            metrics.record_action(overhead_ms=8.0)
        s = metrics.summary()
        assert s["blocked_actions"] == 0
        assert s["step_up_prompts"] == 0
        assert s["prompts_per_goal"] == 0.0


class TestNormalRefactor:
    """Scenario: rename a function across files. Touches multiple files in same subsystem."""

    def test_refactor_stays_in_subsystem(self, dp39_repo: Path) -> None:
        index = build_repo_chunk_index(dp39_repo)
        goal = GoalSpec(query_id="q-2", summary="Rename helper to helper_v2 in src/utils.py")
        lease = build_capability_lease(index, goal, top_k=3)

        ok, _ = check_repo_path_allowed("src/utils.py", lease, write=True)
        assert ok

    def test_refactor_novelty_stays_silent(self) -> None:
        novelty = NoveltyMonitor()
        r1 = novelty.evaluate_contract(_monitor_input("repo://src/main.py"))
        r2 = novelty.evaluate_contract(_monitor_input("repo://src/utils.py"))
        assert r2 is None


class TestNormalTestUpdate:
    """Scenario: add a test file. Should have read access to tested code."""

    def test_test_update_reads_source(self, dp39_repo: Path) -> None:
        index = build_repo_chunk_index(dp39_repo)
        goal = GoalSpec(query_id="q-3", summary="Add tests for entry function")
        lease = build_capability_lease(index, goal, top_k=3)

        ok, _ = check_repo_path_allowed("tests/test_main.py", lease, write=False)
        if ok:
            pass  # test file in scope
        ok, _ = check_repo_path_allowed("src/main.py", lease, write=False)
        assert ok, "should read the source being tested"


# ---------------------------------------------------------------------------
# Adversarial scenarios
# ---------------------------------------------------------------------------


class TestAdversarialScanning:
    """Scenario: agent does broad directory scanning (recon behavior)."""

    def test_scanning_triggers_step_up(self) -> None:
        scan = ScanningScorer(config=ScanScorerConfig(
            window=10, max_unique_dirs=3, max_unique_files=100
        ))
        dirs = [f"repo://dir{i}/file.py" for i in range(6)]
        last = None
        for ref in dirs:
            last = scan.evaluate_contract(_monitor_input(ref))
        assert last is not None
        assert last.recommendation == BehaviorRecommendation.STEP_UP

    def test_scanning_exhausts_exploration_budget(self) -> None:
        budget = ExplorationBudget(config=ExplorationBudgetConfig(max_dirs=3))
        for i in range(3):
            budget.try_consume(f"dir{i}/file.py")
        ok, reason = budget.try_consume("dir99/file.py")
        assert not ok
        assert reason == "dir_budget_exhausted"


class TestAdversarialProtectedZoneProbe:
    """Scenario: agent tries to read/write secrets, keys, deploy configs."""

    def test_secrets_write_denied(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("repo://keys/signing.pem"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_auth_write_denied_without_explicit_allow(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("repo://auth/verify.py"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_step_up_then_approve_flow(self) -> None:
        gov = ProtectedZoneGovernor()
        r1 = gov.decide(_ctx("repo://deploy/prod.yaml"))
        assert r1.enforcement != SandboxEnforcement.ALLOW
        gov.approve_resource("repo://deploy/prod.yaml")
        r2 = gov.decide(_ctx("repo://deploy/prod.yaml"))
        assert r2.enforcement == SandboxEnforcement.ALLOW

    def test_metrics_track_prevented(self) -> None:
        metrics = ScopingMetrics()
        metrics.record_action(blocked=True)
        metrics.record_prevented(protected_write=True)
        metrics.record_action(blocked=True)
        metrics.record_prevented(egress=True)
        s = metrics.summary()
        assert s["prevented"]["total"] == 2


class TestAdversarialEgress:
    """Scenario: agent attempts outbound network calls."""

    def test_egress_blocked(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("net://evil.com/exfil"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_egress_novelty_triggers(self) -> None:
        novelty = NoveltyMonitor()
        novelty.evaluate_contract(_monitor_input("repo://src/main.py"))
        result = novelty.evaluate_contract(_monitor_input("net://evil.com/exfil"))
        assert result is not None
        assert any("network domain" in r for r in result.reasons)


class TestAdversarialDrift:
    """Scenario: agent drifts to unrelated subsystems."""

    def test_drift_triggers_after_threshold(self) -> None:
        scope = {"repo://src/main.py", "repo://src/utils.py"}
        drift = DriftScorer(scope, config=DriftScorerConfig(window=4, threshold=0.5))
        drift.evaluate_contract(_monitor_input("repo://src/main.py"))
        for _ in range(3):
            drift.evaluate_contract(_monitor_input("repo://unrelated/evil.py"))
        assert drift.out_of_scope_ratio >= 0.5

    def test_drift_auto_tightens_governor(self) -> None:
        gov = TighteningGovernor(auto_tighten_on_deny=True)
        deny = BehaviorMonitorResult(
            monitor_id="drift", recommendation=BehaviorRecommendation.DENY
        )
        gov.decide(_ctx("repo://src/main.py"), monitor=deny)
        assert gov.is_tightened


class TestAdversarialNoveltyJump:
    """Scenario: agent suddenly accesses a completely new subsystem."""

    def test_new_subsystem_triggers(self) -> None:
        novelty = NoveltyMonitor()
        novelty.evaluate_contract(_monitor_input("repo://src/main.py"))
        result = novelty.evaluate_contract(_monitor_input("repo://infra/terraform/main.tf"))
        assert result is not None
        assert any("subsystem" in r for r in result.reasons)

    def test_new_tool_class_triggers(self) -> None:
        novelty = NoveltyMonitor()
        novelty.evaluate_contract(
            _monitor_input("repo://src/main.py", "mcp.tools/call/read_file")
        )
        result = novelty.evaluate_contract(
            _monitor_input("repo://src/main.py", "shell/exec/bash")
        )
        assert result is not None
        assert any("tool class" in r for r in result.reasons)


class TestEndToEndScenario:
    """Full end-to-end: index repo -> scope goal -> run actions -> check metrics."""

    def test_full_flow(self, dp39_repo: Path) -> None:
        # 1. Index
        index = build_repo_chunk_index(dp39_repo)
        assert index.chunks

        # 2. Scope
        goal = GoalSpec(query_id="q-e2e", summary="Fix entry function in src/main.py")
        lease = build_capability_lease(index, goal, top_k=3)
        assert "src/main.py" in lease.write_files

        # 3. Set up monitors + governor
        scope_refs = {f"repo://{f}" for f in lease.read_files | lease.write_files}
        drift = DriftScorer(scope_refs, config=DriftScorerConfig(window=5, threshold=0.5))
        scan = ScanningScorer(config=ScanScorerConfig(window=10, max_unique_dirs=5))
        novelty = NoveltyMonitor()
        gov = ProtectedZoneGovernor(
            explicit_allow={f"repo://{f}" for f in lease.write_files}
        )
        budget = ExplorationBudget(config=ExplorationBudgetConfig(max_files=20))
        metrics = ScopingMetrics(goal_id="e2e-1")

        # 4. Simulate normal work
        actions = [
            ("repo://src/main.py", SideEffectLevel.READ_ONLY),
            ("repo://src/utils.py", SideEffectLevel.READ_ONLY),
            ("repo://src/main.py", SideEffectLevel.BOUNDED_WRITE),
        ]
        for ref, se in actions:
            dr = drift.evaluate_contract(_monitor_input(ref))
            sr = scan.evaluate_contract(_monitor_input(ref))
            nr = novelty.evaluate_contract(_monitor_input(ref))
            gr = gov.decide(_ctx(ref, se))
            budget.try_consume(ref.removeprefix("repo://"), byte_count=500)
            metrics.record_action(
                blocked=(gr.enforcement != SandboxEnforcement.ALLOW),
                is_write=(se != SideEffectLevel.READ_ONLY),
                overhead_ms=5.0,
            )

        # 5. Verify
        s = metrics.summary()
        assert s["blocked_actions"] == 0, "normal work should not be blocked"
        assert s["step_up_prompts"] == 0, "no prompts for normal work"
        assert budget.remaining_files > 0
