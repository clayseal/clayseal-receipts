from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

InferenceBackend = Literal["ezkl", "risc0", "sp1"]


@dataclass
class EzklStatus:
    available: bool
    binary: str | None
    message: str


def locate_ezkl() -> EzklStatus:
    env = os.environ.get("EZKL")
    if env and Path(env).is_file():
        return EzklStatus(True, env, "EZKL")
    found = shutil.which("ezkl")
    if found:
        return EzklStatus(True, found, "PATH")
    return EzklStatus(False, None, "ezkl not on PATH")


def fraud_head_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "circuits" / "fraud_head"


def prove_inference(
    *,
    amount: float,
    model_provenance_hash: str,
    output_hash: str,
    allow_stub: bool | None = None,
    backend: InferenceBackend = "ezkl",
) -> bytes | None:
    """Prove fraud-head inference via agent-receipts CLI."""
    from agentauth.receipts.prover import locate_cli

    if backend not in ("ezkl", "risc0", "sp1"):
        raise ValueError(
            f"unsupported inference backend {backend!r}; expected ezkl, risc0, or sp1"
        )

    if allow_stub is None:
        allow_stub = os.environ.get("AGENT_RECEIPTS_ALLOW_STUB", "0") == "1"

    status = locate_cli()
    if not status.available or not status.binary:
        return None

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "inference_proof.json"
        cmd = [
            status.binary,
            "prove-inference",
            "--amount",
            str(float(amount)),
            "--model-provenance-hash",
            model_provenance_hash,
            "--output-hash",
            output_hash,
            "--backend",
            backend,
            "--out",
            str(out),
        ]
        if allow_stub:
            cmd.append("--allow-stub")
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return out.read_bytes()


def verify_inference(envelope_json: bytes, *, allow_stub: bool | None = None) -> dict[str, Any]:
    from agentauth.receipts.prover import locate_cli

    if allow_stub is None:
        allow_stub = os.environ.get("AGENT_RECEIPTS_ALLOW_STUB", "0") == "1"

    status = locate_cli()
    if not status.available or not status.binary:
        return {"valid": False, "reasons": [status.message]}

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "inference.json"
        path.write_bytes(envelope_json)
        cmd = [status.binary, "verify-inference", "--envelope", str(path)]
        if allow_stub:
            cmd.append("--allow-stub")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            return {
                "valid": False,
                "reasons": [detail or "verify-inference failed"],
            }
        valid = "valid=true" in proc.stdout
        return {"valid": valid, "reasons": [] if valid else [proc.stdout.strip()]}


def amount_to_score(amount: float) -> float:
    return min(1.0, float(amount) / 10_000.0)


def load_envelope(blob: bytes) -> dict[str, Any]:
    return json.loads(blob)
