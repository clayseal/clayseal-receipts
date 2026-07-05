"""Shared shell commands for live terminal + comparison UI."""

from __future__ import annotations

DEFAULT_REPO = "examples/poisoned-repo"
INSTALL_CMD = 'pip install -e ".[dev]"'

DEFAULT_TASK = "Fix the failing test in {repo}"


def shell_commands(repo: str = DEFAULT_REPO) -> tuple[str, str]:
    unsecured = f"arctl run-agent --repo {repo}"
    secured = f'{INSTALL_CMD} && arctl run-agent --repo {repo} --receipts'
    return unsecured, secured


UNSECURED_SHELL_CMD, SECURED_SHELL_CMD = shell_commands()
