from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentauth.receipts.policy import NumericRange, Policy


def _is_rust_prover(binary: str) -> bool:
    """Ignore Python `arctl` shims that may appear as agent-receipts on PATH."""
    try:
        proc = subprocess.run(
            [binary, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        text = (proc.stdout or "") + (proc.stderr or "")
        return "prove-policy" in text
    except (OSError, subprocess.TimeoutExpired):
        return False


@dataclass
class ProverStatus:
    available: bool
    binary: str | None
    message: str


def locate_cli() -> ProverStatus:
    env = os.environ.get("AGENT_RECEIPTS_CLI")
    if env and Path(env).is_file():
        return ProverStatus(True, env, "AGENT_RECEIPTS_CLI")

    root = Path(__file__).resolve().parents[2]
    release = root / "target" / "release" / "agent-receipts"
    debug = root / "target" / "debug" / "agent-receipts"
    for candidate in (release, debug):
        if candidate.is_file():
            return ProverStatus(True, str(candidate), "cargo target")

    found = shutil.which("agent-receipts")
    if found and _is_rust_prover(found):
        return ProverStatus(True, found, "PATH")

    return ProverStatus(
        False,
        None,
        "agent-receipts CLI not built; run: cargo build -p agent-receipts-cli --release",
    )


def first_numeric_range(policy: Policy | None) -> NumericRange | None:
    if policy is None:
        return None
    return policy.numeric_ranges[0] if policy.numeric_ranges else None


def prove_structural_policy(
    *,
    policy: Policy | None,
    output: dict[str, Any],
    policy_commitment: str,
    output_hash: str,
    min_score: float | None = None,
    max_score: float | None = None,
    score_field: str = "fraud_score",
) -> bytes | None:
    """
    Generate a Halo2 policy-range proof when the CLI is available.
    Returns JSON bytes of PolicyProofEnvelope, or None if prover unavailable.
    """
    status = locate_cli()
    if not status.available or not status.binary:
        return None

    numeric = first_numeric_range(policy)
    if numeric is None and min_score is not None and max_score is not None:
        numeric = NumericRange(field=score_field, min=float(min_score), max=float(max_score))
    if numeric is None:
        return None

    score = output.get(numeric.field)
    if not isinstance(score, (int, float)):
        return None

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "policy_proof.json"
        output_path = Path(tmp) / "output.json"
        output_path.write_text(json.dumps(output), encoding="utf-8")
        base_cmd = [
            status.binary,
            "prove-policy",
            "--score",
            str(float(score)),
            "--min",
            str(numeric.min),
            "--max",
            str(numeric.max),
            "--policy-commitment",
            policy_commitment,
            "--output-hash",
            output_hash,
            "--out",
            str(out),
        ]
        cmd = list(base_cmd)
        cmd.extend(["--output-json", str(output_path)])
        if policy is not None:
            for field in policy.output_schema_required:
                cmd.extend(["--required-field", field])
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            text = (exc.stdout or "") + (exc.stderr or "")
            if "--output-json" in text or "--required-field" in text:
                raise RuntimeError(
                    "agent-receipts CLI does not support structural policy flags "
                    "(--output-json / --required-field); rebuild the CLI or disable "
                    "required-field proving rather than silently degrading"
                ) from exc
            raise
        return out.read_bytes()


def verify_structural_policy(envelope_json: bytes) -> dict[str, Any]:
    status = locate_cli()
    if not status.available or not status.binary:
        return {
            "valid": False,
            "reasons": [status.message],
        }

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "envelope.json"
        path.write_bytes(envelope_json)
        proc = subprocess.run(
            [status.binary, "verify-policy", "--envelope", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        valid = "valid=true" in proc.stdout
        return {"valid": valid, "reasons": [] if valid else [proc.stdout.strip()]}
