"""Terminal runner for ``arctl run-agent``."""

from __future__ import annotations

import time

from agentauth.receipts.repo_agent.commands import DEFAULT_TASK, shell_commands
from agentauth.receipts.repo_agent.engine import SCENARIO, RepoAgentSession

_CYAN = "\033[36m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _print_cmd(label: str, cmd: str) -> None:
    print(f"{_DIM}{label}:{_RESET} {_CYAN}{cmd}{_RESET}")


def _print_line(kind: str, text: str, *, secured: bool) -> None:
    if kind == "agent":
        prefix = f"{_CYAN}›{_RESET} "
    elif kind == "stderr":
        prefix = f"{_RED}✗{_RESET} "
    elif kind == "system":
        prefix = f"{_YELLOW}•{_RESET} "
    else:
        prefix = "  "
    accent = _GREEN if secured and kind != "stderr" else _RESET
    print(f"{prefix}{accent}{text}{_RESET}")


def run_terminal(
    *,
    repo: str,
    secured: bool,
    both: bool,
    pause: float,
    show_commands: bool,
) -> int:
    unsecured_cmd, secured_cmd = shell_commands(repo)
    task = DEFAULT_TASK.format(repo=repo)

    if show_commands:
        print("Split-terminal — run in two panes:\n")
        _print_cmd("Left (unsecured)", unsecured_cmd)
        _print_cmd("Right (receipts)", secured_cmd)
        print(f"\nTask: {task}\n")
        return 0

    cmd = secured_cmd if secured else unsecured_cmd
    _print_cmd("Run", cmd)
    print(f"{_YELLOW}Repo:{_RESET} {repo}")
    print(f"{_YELLOW}Task:{_RESET} {task}\n")

    if both:
        left = RepoAgentSession(repo=repo)
        left.reset()
        _run_side(left, secured=False, pause=pause)
        right = RepoAgentSession(repo=repo)
        right.reset()
        _run_side(right, secured=True, pause=pause)
        return 0

    session = RepoAgentSession(repo=repo)
    session.reset()
    _run_side(session, secured=secured, pause=pause)
    return 0


def _run_side(session: RepoAgentSession, *, secured: bool, pause: float) -> None:
    side = "receipts" if secured else "unsecured"
    print(f"\n{_YELLOW}── {side} ──{_RESET}\n")

    for _ in SCENARIO:
        beat = session.advance()
        block = beat.secured if secured else beat.unsecured
        for line in block.terminal:
            _print_line(line.kind, line.text, secured=secured)
        if secured and block.receipt:
            r = block.receipt
            tag = f"{_RED}BLOCKED{_RESET}" if r.blocked else f"{_GREEN}receipt{_RESET}"
            valid = "verified" if r.valid else "invalid"
            print(f"  {_DIM}[{tag} {r.tool} · {valid}]{_RESET}")
        if pause > 0 and not beat.done:
            time.sleep(pause)

    if secured:
        verify = session.verify()
        ok = verify.get("all_valid")
        mark = f"{_GREEN}✓{_RESET}" if ok else f"{_RED}✗{_RESET}"
        print(f"\n{mark} Verify session: {verify.get('count', 0)} receipts, all_valid={ok}")
