"""Sandboxed MCP server: exposes file tools through the full dynamic sandboxing stack.

Intended for live Devin testing via ngrok. Takes a repo path and goal text,
builds the complete governor chain, and serves tools over MCP.

Stack:
  ProtectedZoneGovernor → DefaultDenySandboxGovernor → TighteningGovernor
    → RuleBasedSandboxGovernor

Monitors:
  DriftScorer + ScanningScorer + NoveltyMonitor (composite)

Usage:
  AGENT_RECEIPTS_MCP_API_KEY=dev-key python -m agentauth.receipts.sandboxed_server \\
    --repo /path/to/test/repo \\
    --goal "Fix the parse_ticket function" \\
    --transport streamable-http --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.behavior_monitor import BehaviorMonitorResult, BehaviorRecommendation
from agentauth.receipts.default_deny_governor import DefaultDenySandboxGovernor
from agentauth.receipts.drift_monitor import DriftScorer, DriftScorerConfig
from agentauth.receipts.monitor_contract import MonitorInput
from agentauth.receipts.novelty_monitor import NoveltyMonitor
from agentauth.receipts.protected_zone_governor import ProtectedZoneGovernor
from agentauth.receipts.sandbox_builder import build_protected_explicit_allow
from agentauth.core.runtime import SideEffectLevel
from agentauth.receipts.sandbox_governor import RuleBasedSandboxGovernor
from agentauth.receipts.scanning_monitor import ScanningScorer, ScanScorerConfig
from agentauth.receipts.tighten_policy import TighteningGovernor
from agentauth.receipts.mcp import ReceiptedMcpGateway
from agentauth.capabilities.scoping import build_capability_lease, build_repo_chunk_index
from agentauth.capabilities.scoping.capability_scope import apply_lease_to_authority
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.metrics import ScopingMetrics
from agentauth.core.signing import generate_keypair


class _CompositeMonitor:
    def __init__(self, drift: DriftScorer, scan: ScanningScorer, novelty: NoveltyMonitor):
        self.drift = drift
        self.scan = scan
        self.novelty = novelty

    def evaluate_contract(self, contract: MonitorInput) -> BehaviorMonitorResult | None:
        results = []
        for m in (self.drift, self.scan, self.novelty):
            r = m.evaluate_contract(contract)
            if r is not None:
                results.append(r)
        if not results:
            return None
        worst = BehaviorRecommendation.ALLOW
        reasons: list[str] = []
        risk = 0.0
        for r in results:
            if r.recommendation == BehaviorRecommendation.DENY:
                worst = BehaviorRecommendation.DENY
            elif r.recommendation == BehaviorRecommendation.STEP_UP and worst != BehaviorRecommendation.DENY:
                worst = BehaviorRecommendation.STEP_UP
            reasons.extend(r.reasons)
            risk = max(risk, r.risk_score or 0.0)
        return BehaviorMonitorResult(
            monitor_id="composite", monitor_version="v1",
            detector_family="rules", feature_set_id="composite_v1",
            risk_score=risk, threshold=0.3,
            recommendation=worst, reasons=reasons[:10],
        )

    def evaluate(self, ctx: Any) -> BehaviorMonitorResult | None:
        return None


def _build_sandboxed_gateway(
    repo_root: Path,
    goal_text: str,
    query_id: str = "devin-live",
    audit_log: str | None = None,
) -> tuple[ReceiptedMcpGateway, dict[str, Any]]:
    """Build the full sandboxing stack for a repo + goal."""
    print(f"[sandbox] Indexing {repo_root} ...", file=sys.stderr)
    index = build_repo_chunk_index(repo_root)
    print(f"[sandbox] {len(index.chunks)} chunks, {len(index.import_edges)} edges", file=sys.stderr)

    goal = GoalSpec(query_id=query_id, summary=goal_text)
    lease = build_capability_lease(index, goal, top_k=10)
    print(f"[sandbox] Lease: {len(lease.write_files)} write, {len(lease.read_files)} read", file=sys.stderr)
    print(f"[sandbox] Write files: {sorted(lease.write_files)}", file=sys.stderr)

    # Monitors
    scope_refs: set[str] = set()
    for f in lease.write_files:
        scope_refs.add(f"repo_write://{f}")
        scope_refs.add(f"repo_read://{f}")
    for f in lease.read_files - lease.write_files:
        scope_refs.add(f"repo_read://{f}")
    drift = DriftScorer(scope_refs, config=DriftScorerConfig(window=12, threshold=0.5))
    scan = ScanningScorer(config=ScanScorerConfig(window=20, max_unique_dirs=6, max_unique_files=20))
    novelty = NoveltyMonitor()
    for f in lease.read_files | lease.write_files:
        parts = f.replace("\\", "/").strip("/").split("/")
        if parts:
            novelty.approve_subsystem(parts[0])
    novelty.approve_tool_class("mcp.tools/call")
    composite = _CompositeMonitor(drift, scan, novelty)

    # Governor chain
    pk = generate_keypair()
    rules = RuleBasedSandboxGovernor(
        permit_signing_key=pk, permit_ttl_seconds=60,
        lease_ttl_seconds=600, lease_call_budget=100,
        require_active_lease=True,
        honor_monitor_recommendations=True,
        suspend_lease_renewal_on_suspicion=True,
    )
    tightening = TighteningGovernor(inner=rules, auto_tighten_on_deny=True)
    default_deny = DefaultDenySandboxGovernor(inner=tightening)
    explicit_allow = build_protected_explicit_allow(goal, lease)
    protected = ProtectedZoneGovernor(
        inner=default_deny,
        explicit_allow=explicit_allow,
        allow_agent_memory_writes=goal.allow_agent_memory_writes,
    )

    # Agent + Gateway
    tools = ["read_file", "write_file", "list_dir", "grep_repo", "run_shell"]
    policy = Policy.from_dict({
        "version": 1, "name": "sandboxed-devin", "tier": "structural",
        "capability": "fully_proven", "allowed_tools": {"tools": tools},
    })
    cert = dev_certificate(policy.commitment(), scope=tools)
    agent = AgentWrapper(
        model=lambda inp: {},
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=audit_log or ":memory:",
    )
    gw = ReceiptedMcpGateway(
        agent,
        server_name="sandboxed-devin",
        sandbox_governor=protected,
        behavior_monitor=composite,
        query_id=query_id,
        authority_id="sandboxed-devin",
    )

    # Resource ref resolvers
    gw._resource_ref_resolvers["read_file"] = lambda a: (
        f"repo_read://{a.get('path', '')}" if a.get("path") else None
    )
    gw._resource_ref_resolvers["write_file"] = lambda a: (
        f"repo_write://{a.get('path', '')}" if a.get("path") else None
    )
    gw._resource_ref_resolvers["list_dir"] = lambda a: (
        f"repo_read://{a.get('path', '.')}"
    )
    gw._resource_ref_resolvers["grep_repo"] = lambda a: (
        f"repo_read://{a.get('path', '.')}"
    )
    gw._resource_ref_resolvers["run_shell"] = lambda a: (
        f"repo_write://{a.get('cwd', '.')}"
    )

    # Side-effect levels
    _read_tools = {"read_file", "list_dir", "grep_repo"}
    _orig = gw._action_descriptor
    def _patched(tool_name: str, arguments: dict | None = None):
        ad = _orig(tool_name, arguments)
        if tool_name in _read_tools:
            ad.side_effect_level = SideEffectLevel.READ_ONLY
        return ad
    gw._action_descriptor = _patched

    # Register real file handlers
    root = repo_root.resolve()

    def _read_file(args: dict) -> dict:
        path = args.get("path", "")
        target = (root / path).resolve()
        if not str(target).startswith(str(root)):
            return {"error": "path traversal blocked"}
        if not target.is_file():
            return {"error": f"file not found: {path}"}
        return {"content": target.read_text(encoding="utf-8", errors="replace")[:50000]}

    def _write_file(args: dict) -> dict:
        path = args.get("path", "")
        content = args.get("content", "")
        target = (root / path).resolve()
        if not str(target).startswith(str(root)):
            return {"error": "path traversal blocked"}
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"ok": True, "path": path}

    def _list_dir(args: dict) -> dict:
        path = args.get("path", ".")
        target = (root / path).resolve()
        if not str(target).startswith(str(root)):
            return {"error": "path traversal blocked"}
        if not target.is_dir():
            return {"error": f"not a directory: {path}"}
        entries = []
        for item in sorted(target.iterdir()):
            if item.name.startswith("."):
                continue
            rel = item.relative_to(root).as_posix()
            entries.append({"name": rel, "type": "dir" if item.is_dir() else "file"})
        return {"entries": entries[:200]}

    def _grep_repo(args: dict) -> dict:
        pattern = args.get("pattern", "")
        path = args.get("path", ".")
        if not pattern:
            return {"error": "pattern required"}
        target = (root / path).resolve()
        if not str(target).startswith(str(root)):
            return {"error": "path traversal blocked"}
        try:
            result = subprocess.run(
                ["grep", "-rn", "--include=*.py", "--include=*.ts", "--include=*.js",
                 "--include=*.yaml", "--include=*.yml", "-l", pattern, str(target)],
                capture_output=True, text=True, timeout=10,
            )
            files = [
                Path(f).relative_to(root).as_posix()
                for f in result.stdout.strip().splitlines()
                if f
            ]
            return {"matches": files[:50]}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return {"error": "grep failed"}

    def _run_shell(args: dict) -> dict:
        cmd = args.get("cmd", "")
        cwd = args.get("cwd", ".")
        if not cmd:
            return {"error": "cmd required"}
        target = (root / cwd).resolve()
        if not str(target).startswith(str(root)):
            return {"error": "path traversal blocked"}
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=30, cwd=str(target),
            )
            return {
                "stdout": result.stdout[:10000],
                "stderr": result.stderr[:5000],
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"error": "command timed out"}

    gw.register_tool("read_file", _read_file)
    gw.register_tool("write_file", _write_file)
    gw.register_tool("list_dir", _list_dir)
    gw.register_tool("grep_repo", _grep_repo)
    gw.register_tool("run_shell", _run_shell)

    # Seed authority with lease
    gw._capability_lease = lease
    auth = gw.authority()
    apply_lease_to_authority(auth, lease)
    scope: list[str] = []
    for f in lease.write_files:
        scope.append(f"repo_write://{f}")
        scope.append(f"repo_read://{f}")
    for f in lease.read_files - lease.write_files:
        scope.append(f"repo_read://{f}")
    scope.append("mcp_tool_call")
    auth.resource_scope = sorted(set(scope))
    auth.expires_at = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    auth.lease_remaining_calls = 100
    gw.set_authority(auth)

    info = {
        "repo": str(repo_root),
        "goal": goal_text,
        "write_files": sorted(lease.write_files),
        "read_files": sorted(lease.read_files),
        "scope_entries": len(auth.resource_scope),
    }
    print(f"[sandbox] Ready. Scope: {json.dumps(info, indent=2)}", file=sys.stderr)
    return gw, info


def build_sandboxed_mcp(
    repo_root: str,
    goal_text: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    query_id: str = "devin-live",
    audit_log: str | None = None,
):
    """Build a FastMCP app with sandboxed file tools."""
    from mcp.server.fastmcp import FastMCP

    # Import auth helpers from the fraud server
    from agentauth.receipts.mcp.mcp_server import _auth_kwargs

    gw, info = _build_sandboxed_gateway(
        Path(repo_root), goal_text, query_id=query_id, audit_log=audit_log,
    )

    app = FastMCP(
        "agent-receipts-sandbox",
        host=host,
        port=port,
        instructions=(
            f"Sandboxed file tools for: {goal_text}\n"
            f"Write scope: {', '.join(info['write_files'][:10])}\n"
            f"Protected zones (auth/, keys/, deploy/, .env, net://) require explicit approval."
        ),
        **_auth_kwargs(host, port),
    )

    @app.tool()
    def read_file(path: str) -> dict:
        """Read a file from the repository."""
        result = gw.call_tool("read_file", {"path": path})
        if result.blocked:
            return {"error": "blocked", "violations": result.policy_violations[:3]}
        return result.output.get("result", {})

    @app.tool()
    def write_file(path: str, content: str) -> dict:
        """Write content to a file in the repository."""
        result = gw.call_tool("write_file", {"path": path, "content": content})
        if result.blocked:
            return {"error": "blocked", "violations": result.policy_violations[:3]}
        return result.output.get("result", {})

    @app.tool()
    def list_dir(path: str = ".") -> dict:
        """List directory contents."""
        result = gw.call_tool("list_dir", {"path": path})
        if result.blocked:
            return {"error": "blocked", "violations": result.policy_violations[:3]}
        return result.output.get("result", {})

    @app.tool()
    def grep_repo(pattern: str, path: str = ".") -> dict:
        """Search for a pattern in the repository."""
        result = gw.call_tool("grep_repo", {"pattern": pattern, "path": path})
        if result.blocked:
            return {"error": "blocked", "violations": result.policy_violations[:3]}
        return result.output.get("result", {})

    @app.tool()
    def run_shell(cmd: str, cwd: str = ".") -> dict:
        """Run a shell command in the repository."""
        result = gw.call_tool("run_shell", {"cmd": cmd, "cwd": cwd})
        if result.blocked:
            return {"error": "blocked", "violations": result.policy_violations[:3]}
        return result.output.get("result", {})

    return app


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Sandboxed MCP server for Devin testing")
    parser.add_argument("--repo", required=True, help="Path to the repository to sandbox")
    parser.add_argument("--goal", required=True, help="Goal text for capability scoping")
    parser.add_argument("--query-id", default="devin-live")
    parser.add_argument("--audit-log", default=None, help="SQLite audit log path")
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default=os.environ.get("AGENT_RECEIPTS_MCP_TRANSPORT", "stdio"),
    )
    parser.add_argument("--host", default=os.environ.get("AGENT_RECEIPTS_MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("AGENT_RECEIPTS_MCP_PORT", "8000")))
    args = parser.parse_args(argv)

    repo_path = Path(args.repo).resolve()
    if not repo_path.is_dir():
        raise SystemExit(f"repo not found: {args.repo}")

    app = build_sandboxed_mcp(
        str(repo_path), args.goal,
        host=args.host, port=args.port,
        query_id=args.query_id,
        audit_log=args.audit_log,
    )
    app.run(transport=args.transport)


if __name__ == "__main__":
    main()
