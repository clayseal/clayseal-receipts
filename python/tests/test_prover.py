from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from agentauth.receipts.policy import Policy
from agentauth.receipts.prover import ProverStatus, prove_structural_policy

ROOT = Path(__file__).resolve().parents[2]


def test_prove_structural_policy_rejects_older_cli_without_structural_flags(
    monkeypatch: pytest.MonkeyPatch,
):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")

    monkeypatch.setattr(
        "agentauth.receipts.prover.locate_cli",
        lambda: ProverStatus(True, "/tmp/fake-agent-receipts", "test"),
    )

    def fake_run(cmd: list[str], check: bool, capture_output: bool, text: bool):
        del check, capture_output, text
        if "--output-json" in cmd:
            raise subprocess.CalledProcessError(
                2,
                cmd,
                stderr="error: unexpected argument '--output-json' found",
            )
        raise AssertionError("fallback proving must not run")

    monkeypatch.setattr("agentauth.receipts.prover.subprocess.run", fake_run)

    with pytest.raises(RuntimeError, match="does not support structural policy flags"):
        prove_structural_policy(
            policy=policy,
            output={"decision": "approve", "fraud_score": 0.25},
            policy_commitment="commitment",
            output_hash="hash",
        )


def test_prove_structural_policy_reraises_non_compatibility_errors(
    monkeypatch: pytest.MonkeyPatch,
):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")

    monkeypatch.setattr(
        "agentauth.receipts.prover.locate_cli",
        lambda: ProverStatus(True, "/tmp/fake-agent-receipts", "test"),
    )

    def fake_run(cmd: list[str], check: bool, capture_output: bool, text: bool):
        del check, capture_output, text
        raise subprocess.CalledProcessError(2, cmd, stderr="policy circuit failed")

    monkeypatch.setattr("agentauth.receipts.prover.subprocess.run", fake_run)

    with pytest.raises(subprocess.CalledProcessError):
        prove_structural_policy(
            policy=policy,
            output={"decision": "approve", "fraud_score": 0.25},
            policy_commitment="commitment",
            output_hash="hash",
        )
