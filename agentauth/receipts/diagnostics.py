"""Environment readiness checks for design partner onboarding."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from agentauth.receipts._version import __version__
from agentauth.receipts.prover import locate_cli

ROOT = Path(__file__).resolve().parents[2]
KEYS_DIR = ROOT / "keys"
POLICY_PARAMS = KEYS_DIR / "policy_range_params.bin"


def _check(name: str, ok: bool, detail: str, *, required: bool = True) -> dict[str, Any]:
    return {"name": name, "ok": ok, "required": required, "detail": detail}


def run_diagnostics(*, require_prover: bool = False) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    checks.append(
        _check(
            "python_version",
            sys.version_info >= (3, 10),
            f"{sys.version_info.major}.{sys.version_info.minor}",
        )
    )
    checks.append(_check("sdk_version", True, __version__, required=False))

    cli = locate_cli()
    checks.append(
        _check(
            "prover_cli",
            cli.available,
            cli.message if cli.available else cli.message,
            required=require_prover,
        )
    )

    if cli.available and cli.binary:
        checks.append(_check("prover_binary", True, cli.binary, required=require_prover))
    else:
        checks.append(
            _check("prover_binary", False, "not found", required=require_prover)
        )

    keys_ok = POLICY_PARAMS.is_file()
    checks.append(
        _check(
            "policy_proving_keys",
            keys_ok,
            (
                str(POLICY_PARAMS)
                if keys_ok
                else "missing; run: cargo run -p agent-receipts-cli -- setup"
            ),
            required=require_prover,
        )
    )

    mcp_ok = importlib.util.find_spec("mcp") is not None
    checks.append(
        _check(
            "mcp_sdk",
            mcp_ok,
            "pip install 'agent-receipts[mcp]'" if not mcp_ok else "installed",
            required=False,
        )
    )

    policy_path = ROOT / "policies" / "fraud_decision.yaml"
    checks.append(
        _check(
            "example_policy",
            policy_path.is_file(),
            str(policy_path),
            required=False,
        )
    )

    required_failed = [c for c in checks if c["required"] and not c["ok"]]
    optional_failed = [c for c in checks if not c["required"] and not c["ok"]]

    return {
        "ready": len(required_failed) == 0,
        "prove_ready": cli.available and keys_ok,
        "checks": checks,
        "required_failures": [c["name"] for c in required_failed],
        "optional_gaps": [c["name"] for c in optional_failed],
    }


def diagnostics_json(*, require_prover: bool = False, indent: int = 2) -> str:
    return json.dumps(run_diagnostics(require_prover=require_prover), indent=indent)
