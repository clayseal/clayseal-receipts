"""Repo bootstrap sandboxing + command execution attestation (RT-3 / H3–H7)."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any

from agentauth.core.hash_util import hash_canonical_json, sha256_hex

_DEFAULT_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "PYTHONPATH",
    "PYTHONHASHSEED",
    "CI",
    "GITHUB_*",
)

_SUBMODULE_DENY_RE = r"(?i)submodule\b[^\n]*--recursive|--init\s+--recursive"


@dataclass
class BootstrapPolicy:
    enabled: bool = False
    deny_recursive_submodules: bool = True
    require_sandbox_for_commands: bool = False
    env_allowlist: list[str] = field(default_factory=lambda: list(_DEFAULT_ENV_ALLOWLIST))
    record_command_receipts: bool = True

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> BootstrapPolicy:
        if not isinstance(raw, dict):
            return cls()
        env = raw.get("env_allowlist") or raw.get("allowed_env")
        return cls(
            enabled=bool(raw.get("enabled", False)),
            deny_recursive_submodules=bool(raw.get("deny_recursive_submodules", True)),
            require_sandbox_for_commands=bool(raw.get("require_sandbox_for_commands", False)),
            env_allowlist=[str(item) for item in (env or _DEFAULT_ENV_ALLOWLIST)],
            record_command_receipts=bool(raw.get("record_command_receipts", True)),
        )


@dataclass
class CommandExecutionAttestation:
    argv: list[str]
    cwd: str
    env_allowlist: list[str]
    stdout_hash: str | None = None
    stderr_hash: str | None = None
    exit_code: int | None = None
    sandboxed: bool = False
    sandbox_mechanism: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "cwd": self.cwd,
            "env_allowlist": list(self.env_allowlist),
            "stdout_hash": self.stdout_hash,
            "stderr_hash": self.stderr_hash,
            "exit_code": self.exit_code,
            "sandboxed": self.sandboxed,
            "sandbox_mechanism": self.sandbox_mechanism,
            "commitment": hash_canonical_json(
                {
                    "argv": self.argv,
                    "cwd": self.cwd,
                    "stdout_hash": self.stdout_hash,
                    "stderr_hash": self.stderr_hash,
                }
            ),
        }


def build_command_attestation(
    command: str,
    *,
    cwd: str,
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = None,
    sandboxed: bool = False,
    sandbox_mechanism: str | None = None,
    env_allowlist: list[str] | None = None,
) -> CommandExecutionAttestation:
    return CommandExecutionAttestation(
        argv=shlex.split(command),
        cwd=cwd,
        env_allowlist=list(env_allowlist or _DEFAULT_ENV_ALLOWLIST),
        stdout_hash=sha256_hex(stdout.encode("utf-8")) if stdout else None,
        stderr_hash=sha256_hex(stderr.encode("utf-8")) if stderr else None,
        exit_code=exit_code,
        sandboxed=sandboxed,
        sandbox_mechanism=sandbox_mechanism,
    )


def submodule_recursive_violations(command: str, *, policy: BootstrapPolicy) -> list[str]:
    if not policy.enabled or not policy.deny_recursive_submodules:
        return []
    import re

    if re.search(_SUBMODULE_DENY_RE, command):
        return ["recursive git submodule init is not authorized without explicit grant"]
    return []


def evaluate_bootstrap_command(
    command: str,
    *,
    policy: BootstrapPolicy,
    sandboxed: bool,
    sandbox_mechanism: str | None,
) -> list[str]:
    violations = submodule_recursive_violations(command, policy=policy)
    if (
        policy.enabled
        and policy.require_sandbox_for_commands
        and not sandboxed
    ):
        violations.append(
            "command execution requires sandbox isolation but none was applied"
        )
    return violations
