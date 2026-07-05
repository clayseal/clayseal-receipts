"""Anomaly score verifiability (SM-25 / README §3.1).

Commits the feature vector + model weights and supports offline recomputation of
``score = model(features)``. When the agent-receipts CLI is available, emits a
stub EZKL-style envelope for future circuit binding.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentauth.receipts.anomaly_baseline import AnomalyBaselineModel
from agentauth.core.hash_util import hash_canonical_json

ANOMALY_PROOF_SCHEMA = "agent-receipts.anomaly-score-proof.v1"


@dataclass
class AnomalyScoreProof:
    model_commitment: str
    feature_vector: list[float]
    score: float
    proof_kind: str = "recomputable"
    ezkl_envelope: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": ANOMALY_PROOF_SCHEMA,
            "model_commitment": self.model_commitment,
            "feature_vector": [round(value, 6) for value in self.feature_vector],
            "score": round(self.score, 6),
            "proof_kind": self.proof_kind,
            "commitment": hash_canonical_json(
                {
                    "model_commitment": self.model_commitment,
                    "feature_vector": [round(value, 6) for value in self.feature_vector],
                    "score": round(self.score, 6),
                }
            ),
        }
        if self.ezkl_envelope is not None:
            payload["ezkl_envelope"] = self.ezkl_envelope
        return payload


def build_anomaly_score_proof(
    *,
    model: AnomalyBaselineModel,
    feature_vector: list[float],
    score: float,
    allow_stub: bool | None = None,
) -> AnomalyScoreProof:
    proof = AnomalyScoreProof(
        model_commitment=model.model_commitment(),
        feature_vector=list(feature_vector),
        score=float(score),
    )
    envelope = try_prove_anomaly_ezkl(
        model_commitment=model.model_commitment(),
        feature_vector=feature_vector,
        score=score,
        allow_stub=allow_stub,
    )
    if envelope is not None:
        proof.proof_kind = str(envelope.get("backend", "ezkl_stub"))
        proof.ezkl_envelope = envelope
    return proof


def verify_anomaly_score_proof(
    proof: dict[str, Any],
    *,
    model: AnomalyBaselineModel | None = None,
) -> dict[str, Any]:
    """Recompute and verify an anomaly score proof."""
    reasons: list[str] = []
    if proof.get("schema") != ANOMALY_PROOF_SCHEMA:
        return {"valid": False, "reasons": ["unsupported anomaly proof schema"]}

    features = proof.get("feature_vector")
    score = proof.get("score")
    model_commitment = proof.get("model_commitment")
    if not isinstance(features, list) or not isinstance(score, (int, float)):
        return {"valid": False, "reasons": ["missing feature_vector or score"]}

    if model is not None:
        if model.model_commitment() != model_commitment:
            reasons.append("model_commitment does not match supplied model")
        expected = model.score([float(item) for item in features])
        if abs(expected - float(score)) > 1e-4:
            reasons.append(
                f"score {score} does not match recomputed {expected:.6f} for feature vector"
            )

    commitment_inputs = {
        "model_commitment": model_commitment,
        "feature_vector": [round(float(item), 6) for item in features],
        "score": round(float(score), 6),
    }
    expected_commitment = hash_canonical_json(commitment_inputs)
    if proof.get("commitment") != expected_commitment:
        reasons.append("proof commitment does not match feature_vector + score")

    envelope = proof.get("ezkl_envelope")
    if isinstance(envelope, dict) and envelope.get("valid") is False:
        reasons.append("ezkl envelope marked invalid")

    return {"valid": not reasons, "reasons": reasons}


def try_prove_anomaly_ezkl(
    *,
    model_commitment: str,
    feature_vector: list[float],
    score: float,
    allow_stub: bool | None = None,
) -> dict[str, Any] | None:
    """Optional CLI-backed stub envelope for future EZKL anomaly circuit."""
    from agentauth.receipts.prover import locate_cli

    if allow_stub is None:
        allow_stub = os.environ.get("AGENT_RECEIPTS_ALLOW_STUB", "1") == "1"

    status = locate_cli()
    if not status.available or not status.binary:
        if allow_stub:
            return {
                "backend": "recomputable_stub",
                "valid": True,
                "model_commitment": model_commitment,
                "feature_vector_hash": hash_canonical_json(feature_vector),
                "score": round(float(score), 6),
                "note": "EZKL anomaly circuit not provisioned; recomputable commitment only",
            }
        return None

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "anomaly_proof.json"
        cmd = [
            status.binary,
            "prove-inference",
            "--amount",
            str(float(score)),
            "--model-provenance-hash",
            model_commitment,
            "--output-hash",
            hash_canonical_json({"score": score, "features": feature_vector}),
            "--backend",
            "ezkl",
            "--out",
            str(out),
        ]
        if allow_stub:
            cmd.append("--allow-stub")
        try:
            import subprocess

            proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if proc.returncode != 0 or not out.is_file():
                if allow_stub:
                    return {
                        "backend": "recomputable_stub",
                        "valid": True,
                        "model_commitment": model_commitment,
                        "feature_vector_hash": hash_canonical_json(feature_vector),
                        "score": round(float(score), 6),
                    }
                return None
            envelope = json.loads(out.read_text(encoding="utf-8"))
            return {
                "backend": "ezkl",
                "valid": True,
                "envelope": envelope,
                "model_commitment": model_commitment,
                "score": round(float(score), 6),
            }
        except (OSError, json.JSONDecodeError):
            if allow_stub:
                return {
                    "backend": "recomputable_stub",
                    "valid": True,
                    "model_commitment": model_commitment,
                    "feature_vector_hash": hash_canonical_json(feature_vector),
                    "score": round(float(score), 6),
                }
            return None
