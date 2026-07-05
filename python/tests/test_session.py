"""Session proof aggregation tests (SOTA-7)."""

from __future__ import annotations

import json

import pytest

from agentauth.receipts.prover import locate_cli
from agentauth.receipts.session import prove_session, verify_session


def _sample_actions(n: int = 3) -> list[dict]:
    return [
        {
            "score": 0.1 * (i + 1),
            "min": 0.0,
            "max": 1.0,
            "policy_commitment": "pol-session",
            "output_hash": f"out-{i}",
            "required_fields": ["decision", "fraud_score"],
            "output": {"decision": "approve", "fraud_score": 0.1 * (i + 1)},
        }
        for i in range(n)
    ]


@pytest.mark.skipif(not locate_cli().available, reason="agent-receipts CLI not built")
def test_session_batch_roundtrip():
    blob = prove_session(session_id="sess-py", actions=_sample_actions(2))
    assert blob is not None
    env = json.loads(blob)
    assert env["aggregation_mode"] == "halo2_batch_v1"
    assert env["action_count"] == 2
    check = verify_session(blob)
    assert check["valid"] is True


@pytest.mark.skipif(not locate_cli().available, reason="agent-receipts CLI not built")
def test_session_nova_fold_roundtrip():
    blob = prove_session(
        session_id="sess-fold",
        actions=_sample_actions(2),
        mode="nova_fold_v1",
    )
    assert blob is not None
    env = json.loads(blob)
    assert env["aggregation_mode"] == "nova_fold_v1"
    check = verify_session(blob)
    assert check["valid"] is True
