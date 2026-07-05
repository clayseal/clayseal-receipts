from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

InferenceBackend = Literal["ezkl", "risc0", "sp1"]


def _allow_stub_for_prove(allow_stub: bool | None) -> bool:
    if allow_stub is not None:
        return allow_stub
    return os.environ.get("AGENT_RECEIPTS_ALLOW_STUB", "0") == "1"


def _allow_stub_for_verify(allow_stub: bool | None) -> bool:
    if allow_stub is not None:
        return allow_stub
    return os.environ.get("AGENT_RECEIPTS_ALLOW_STUB", "0") == "1"


@dataclass
class ComposedBindings:
    output_hash: str
    policy_commitment: str
    model_provenance_hash: str
    context_hash: str
    public_score: float


def prove_composed(
    *,
    amount: float,
    fraud_score: float,
    policy_commitment: str,
    model_provenance_hash: str,
    output_hash: str,
    context_hash: str,
    min_score: float | None = None,
    max_score: float | None = None,
    policy: Any | None = None,
    allow_stub: bool | None = None,
    recursive: bool = False,
    backend: InferenceBackend = "ezkl",
) -> bytes | None:
    """Policy + inference + compose. Uses per-backend inference via compose_from_parts."""
    from agentauth.receipts.inference import prove_inference
    from agentauth.receipts.policy import Policy
    from agentauth.receipts.prover import first_numeric_range, locate_cli, prove_structural_policy

    if policy is not None:
        if not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy instance when provided")
        numeric = first_numeric_range(policy)
        if numeric is None:
            raise ValueError("composed proving requires policy.numeric_ranges")
        min_score = float(numeric.min)
        max_score = float(numeric.max)
        score_field = numeric.field
    else:
        score_field = "fraud_score"
        if min_score is None or max_score is None:
            min_score = 0.0 if min_score is None else min_score
            max_score = 1.0 if max_score is None else max_score

    if allow_stub is None:
        allow_stub = _allow_stub_for_prove(None)

    status = locate_cli()
    if not status.available or not status.binary:
        return None

    if recursive and backend == "ezkl":
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "composed.json"
            cmd = [
                status.binary,
                "prove-composed",
                "--amount",
                str(float(amount)),
                "--fraud-score",
                str(float(fraud_score)),
                "--min",
                str(min_score),
                "--max",
                str(max_score),
                "--policy-commitment",
                policy_commitment,
                "--model-provenance-hash",
                model_provenance_hash,
                "--output-hash",
                output_hash,
                "--context-hash",
                context_hash,
                "--out",
                str(out),
                "--recursive",
            ]
            if allow_stub:
                cmd.append("--allow-stub")
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return out.read_bytes()

    policy_output = {"decision": "approve", score_field: fraud_score}
    policy_proof = prove_structural_policy(
        policy=policy,
        output=policy_output,
        policy_commitment=policy_commitment,
        output_hash=output_hash,
        min_score=min_score,
        max_score=max_score,
        score_field=score_field,
    )
    if policy_proof is None:
        return None

    inference_proof = prove_inference(
        amount=amount,
        model_provenance_hash=model_provenance_hash,
        output_hash=output_hash,
        allow_stub=allow_stub,
        backend=backend,
    )
    if inference_proof is None:
        return None

    return compose_from_parts(
        policy_proof=policy_proof,
        inference_proof=inference_proof,
        bindings=ComposedBindings(
            output_hash=output_hash,
            policy_commitment=policy_commitment,
            model_provenance_hash=model_provenance_hash,
            context_hash=context_hash,
            public_score=fraud_score,
        ),
    )


def verify_composed(envelope_json: bytes, *, allow_stub: bool | None = None) -> dict[str, Any]:
    from agentauth.receipts.prover import locate_cli

    if allow_stub is None:
        allow_stub = _allow_stub_for_verify(None)

    status = locate_cli()
    if not status.available or not status.binary:
        return {"valid": False, "reasons": [status.message]}

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "composed.json"
        path.write_bytes(envelope_json)
        cmd = [status.binary, "verify-composed", "--envelope", str(path)]
        if allow_stub:
            cmd.append("--allow-stub")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            return {
                "valid": False,
                "reasons": [detail or "verify-composed failed"],
            }
        valid = "valid=true" in proc.stdout
        return {"valid": valid, "reasons": [] if valid else [proc.stdout.strip()]}


def compose_from_parts(
    *,
    policy_proof: bytes,
    inference_proof: bytes,
    bindings: ComposedBindings,
) -> bytes | None:
    from agentauth.receipts.prover import locate_cli

    status = locate_cli()
    if not status.available or not status.binary:
        return None

    with tempfile.TemporaryDirectory() as tmp:
        policy_path = Path(tmp) / "policy.json"
        inference_path = Path(tmp) / "inference.json"
        out = Path(tmp) / "composed.json"
        policy_path.write_bytes(policy_proof)
        inference_path.write_bytes(inference_proof)
        subprocess.run(
            [
                status.binary,
                "compose",
                "--policy",
                str(policy_path),
                "--inference",
                str(inference_path),
                "--output-hash",
                bindings.output_hash,
                "--policy-commitment",
                bindings.policy_commitment,
                "--model-provenance-hash",
                bindings.model_provenance_hash,
                "--context-hash",
                bindings.context_hash,
                "--public-score",
                str(bindings.public_score),
                "--out",
                str(out),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return out.read_bytes()


def parse_composed(blob: bytes) -> dict[str, Any]:
    return json.loads(blob)


def verify_composed_execution_bindings(
    envelope_json: bytes,
    *,
    expected_context_hash: str | None = None,
    expected_model_provenance_hash: str | None = None,
) -> list[str]:
    """Cross-check composed envelope bindings against execution proof / certificate."""
    try:
        data = json.loads(envelope_json)
    except json.JSONDecodeError:
        return ["composed proof envelope is not valid JSON"]

    if not isinstance(data, dict):
        return ["composed proof envelope must be a JSON object"]

    bindings = data.get("bindings", {})
    if not isinstance(bindings, dict):
        return ["composed proof bindings missing or invalid"]

    reasons: list[str] = []
    if expected_context_hash is not None:
        actual = bindings.get("context_hash")
        if actual != expected_context_hash:
            reasons.append("composed bindings context_hash does not match execution proof")
    if expected_model_provenance_hash is not None:
        binding_model = bindings.get("model_provenance_hash")
        if binding_model != expected_model_provenance_hash:
            reasons.append("composed bindings model_provenance_hash does not match certificate")
        inference = data.get("inference", {})
        if isinstance(inference, dict):
            inference_model = inference.get("model_provenance_hash")
            if inference_model and inference_model != expected_model_provenance_hash:
                reasons.append(
                    "composed inference model_provenance_hash does not match certificate"
                )
    return reasons
