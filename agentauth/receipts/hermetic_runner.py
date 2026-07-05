"""Hermetic / egress-isolated command execution (H3–H7 / F6 mitigation)."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

_DEFAULT_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "CI",
    "GITHUB_*",
)


@dataclass
class HermeticRunnerPolicy:
    """Posture for running untrusted test/build commands."""

    require_egress_isolation: bool = True
    require_hermetic_python: bool = True
    env_allowlist: list[str] = field(default_factory=lambda: list(_DEFAULT_ENV_ALLOWLIST))
    deny_on_missing_sandbox: bool = True
    sandbox_mechanisms: list[str] = field(default_factory=lambda: ["unshare-netns"])

    @classmethod
    def from_test_execution_dict(cls, raw: dict[str, Any] | None) -> HermeticRunnerPolicy:
        if not isinstance(raw, dict):
            return cls()
        env = raw.get("env_allowlist") or raw.get("allowed_env")
        return cls(
            require_egress_isolation=bool(raw.get("require_egress_isolation", True)),
            require_hermetic_python=bool(raw.get("require_hermetic_python", True)),
            env_allowlist=[str(item) for item in (env or _DEFAULT_ENV_ALLOWLIST)],
            deny_on_missing_sandbox=bool(raw.get("deny_on_missing_sandbox", True)),
        )


def detect_egress_sandbox() -> tuple[list[str], str | None]:
    """Return argv prefix for network-isolated child processes when available."""
    if shutil.which("unshare") is None:
        return [], None
    probe = subprocess.run(
        ["unshare", "-r", "-n", "true"],
        capture_output=True,
        check=False,
    )
    if probe.returncode == 0:
        return ["unshare", "-r", "-n"], "unshare-netns"
    return [], None


def hermetic_child_env(
    *,
    policy: HermeticRunnerPolicy | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build a minimized environment that disables user-site auto-import (sitecustomize)."""
    cfg = policy or HermeticRunnerPolicy()
    out: dict[str, str] = {}
    for key, value in os.environ.items():
        if any(
            key == allowed.rstrip("*")
            or (allowed.endswith("*") and key.startswith(allowed[:-1]))
            for allowed in cfg.env_allowlist
        ):
            out[key] = value
    if cfg.require_hermetic_python:
        out["PYTHONNOUSERSITE"] = "1"
        out["PYTHONSAFEPATH"] = "1"
        out.pop("PYTHONUSERBASE", None)
    if extra:
        out.update(extra)
    return out


def evaluate_test_execution_posture(
    *,
    policy: HermeticRunnerPolicy | None = None,
    commands: list[str] | None = None,
) -> list[str]:
    """Return violations when policy requires isolation but sandbox is unavailable."""
    cfg = policy or HermeticRunnerPolicy()
    if not commands:
        return []
    if not cfg.require_egress_isolation:
        return []
    _, mechanism = detect_egress_sandbox()
    if mechanism is None and cfg.deny_on_missing_sandbox:
        return [
            "required_tests_unsandboxed: policy requires egress-isolated test execution "
            "but no sandbox (e.g. unshare -rn) is available"
        ]
    return []


def run_hermetic_command(
    command: str,
    *,
    cwd: str,
    timeout: int = 60,
    policy: HermeticRunnerPolicy | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run a shell command under egress isolation + hermetic Python env when possible."""
    cfg = policy or HermeticRunnerPolicy()
    prefix, mechanism = detect_egress_sandbox()
    if cfg.require_egress_isolation and mechanism is None and cfg.deny_on_missing_sandbox:
        return {
            "command": command,
            "exit_code": 127,
            "stdout": "",
            "stderr": "egress isolation required but unavailable",
            "sandboxed": False,
            "sandbox_mechanism": None,
            "timed_out": False,
        }
    env = hermetic_child_env(policy=cfg, extra=extra_env)
    argv = [*prefix, "sh", "-lc", command]
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": command,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "sandboxed": bool(prefix),
            "sandbox_mechanism": mechanism,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "exit_code": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "sandboxed": bool(prefix),
            "sandbox_mechanism": mechanism,
            "timed_out": True,
        }


def command_argv_summary(command: str) -> list[str]:
    return shlex.split(command)
