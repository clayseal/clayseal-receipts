"""Witness co-signing of checkpoints: quorum verification + equivocation refusal (SOTA-5)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from agentauth.receipts.audit import AuditChain, count_valid_witness_cosignatures
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.core.signing import generate_keypair
from agentauth.receipts.witness import (
    Witness,
    WitnessRefusal,
    add_witness_cosignature,
    create_witness_app,
)


def _proof(i: int) -> ExecutionProof:
    return ExecutionProof(
        proof_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        certificate_ref="cert",
        policy_commitment="pc",
        context_hash="ch",
        output_hash=f"oh{i}",
        attestation_path=AttestationPath.SHADOW,
        policy_satisfied=True,
        decision_outcome=DecisionOutcome.ALLOW,
        authority_version=1,
        session_id=None,
        created_at=datetime.now(timezone.utc),
    )


def _grow(chain: AuditChain, *, start: int, n: int) -> None:
    for i in range(start, start + n):
        chain.append(_proof(i), action=f"act{i}")


# --- co-sign accept + quorum verification ---


def test_witness_cosign_then_quorum_verify():
    log_key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=log_key)
    _grow(chain, start=0, n=3)
    early = chain.signed_checkpoint()

    witness = Witness(generate_keypair(), log_public_key=log_key.public_key_hex)
    witness.cosign(early)  # first sighting — bootstraps last_seen

    _grow(chain, start=10, n=4)
    now = chain.signed_checkpoint()
    proof = chain.consistency_proof(early["count"], now["count"])
    witness.cosign(now, consistency_proof=proof)

    assert count_valid_witness_cosignatures(now) == 1
    assert chain.verify_checkpoint(now, required_witnesses=1) is True
    # the unwitnessed earlier checkpoint no longer matches the grown chain anyway
    assert chain.verify_checkpoint(now, required_witnesses=2) is False


def test_quorum_threshold_and_trusted_keys():
    log_key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=log_key)
    _grow(chain, start=0, n=5)
    ckpt = chain.signed_checkpoint()

    w1, w2 = generate_keypair(), generate_keypair()
    Witness(w1, log_public_key=log_key.public_key_hex).cosign(ckpt)
    Witness(w2, log_public_key=log_key.public_key_hex).cosign(ckpt)

    assert count_valid_witness_cosignatures(ckpt) == 2
    assert chain.verify_checkpoint(ckpt, required_witnesses=2) is True
    assert chain.verify_checkpoint(ckpt, required_witnesses=3) is False

    # Only w1 is trusted -> quorum of 2 from the trusted set fails.
    trusted = {w1.public_key_hex}
    assert count_valid_witness_cosignatures(ckpt, trusted_keys=trusted) == 1
    assert (
        chain.verify_checkpoint(ckpt, required_witnesses=2, trusted_witness_keys=trusted)
        is False
    )
    assert (
        chain.verify_checkpoint(ckpt, required_witnesses=1, trusted_witness_keys=trusted)
        is True
    )


def test_duplicate_cosignature_counts_once():
    chain = AuditChain.in_memory(signing_key=generate_keypair())
    _grow(chain, start=0, n=2)
    ckpt = chain.signed_checkpoint()
    key = generate_keypair()
    add_witness_cosignature(ckpt, key, allow_unsafe=True)
    add_witness_cosignature(ckpt, key, allow_unsafe=True)  # same witness signs twice
    assert len(ckpt["witness_cosignatures"]) == 2
    assert count_valid_witness_cosignatures(ckpt) == 1


def test_tampered_cosignature_not_counted():
    chain = AuditChain.in_memory(signing_key=generate_keypair())
    _grow(chain, start=0, n=2)
    ckpt = chain.signed_checkpoint()
    add_witness_cosignature(ckpt, generate_keypair(), allow_unsafe=True)
    ckpt["merkle_root"] = "deadbeef"  # mutate the core after co-signing
    assert count_valid_witness_cosignatures(ckpt) == 0


# --- equivocation / split-view refusal ---


def test_witness_refuses_split_view_same_size():
    log_key = generate_keypair()
    chain_a = AuditChain.in_memory(signing_key=log_key)
    _grow(chain_a, start=0, n=3)
    ckpt_a = chain_a.signed_checkpoint()

    witness = Witness(generate_keypair())
    witness.cosign(ckpt_a)

    # A forked log with different records at the SAME size = split view.
    chain_b = AuditChain.in_memory(signing_key=log_key)
    _grow(chain_b, start=100, n=3)
    ckpt_b = chain_b.signed_checkpoint()
    assert ckpt_b["count"] == ckpt_a["count"]
    assert ckpt_b["merkle_root"] != ckpt_a["merkle_root"]

    with pytest.raises(WitnessRefusal, match="split view"):
        witness.cosign(ckpt_b)


def test_witness_refuses_forked_growth_with_bogus_proof():
    log_key = generate_keypair()
    chain_a = AuditChain.in_memory(signing_key=log_key)
    _grow(chain_a, start=0, n=3)
    ckpt_a = chain_a.signed_checkpoint()

    witness = Witness(generate_keypair())
    witness.cosign(ckpt_a)

    # Forked history (different early records), grown to size 5, with its own
    # internally-valid consistency proof — but it is not consistent with ckpt_a.
    chain_b = AuditChain.in_memory(signing_key=log_key)
    _grow(chain_b, start=100, n=5)
    ckpt_b = chain_b.signed_checkpoint()
    forged_proof = chain_b.consistency_proof(3, 5)

    with pytest.raises(WitnessRefusal, match="equivocation"):
        witness.cosign(ckpt_b, consistency_proof=forged_proof)


def test_witness_refuses_growth_without_proof():
    chain = AuditChain.in_memory(signing_key=generate_keypair())
    _grow(chain, start=0, n=2)
    witness = Witness(generate_keypair())
    witness.cosign(chain.signed_checkpoint())
    _grow(chain, start=10, n=2)
    with pytest.raises(WitnessRefusal, match="consistency proof"):
        witness.cosign(chain.signed_checkpoint())


def test_witness_refuses_regression():
    chain = AuditChain.in_memory(signing_key=generate_keypair())
    _grow(chain, start=0, n=5)
    big = chain.signed_checkpoint()
    witness = Witness(generate_keypair())
    witness.cosign(big)
    small = {**big, "count": 3}
    with pytest.raises(WitnessRefusal, match="regress"):
        witness.cosign(small)


def test_witness_pins_log_key():
    log_key = generate_keypair()
    impostor = generate_keypair()
    chain = AuditChain.in_memory(signing_key=impostor)
    _grow(chain, start=0, n=3)
    ckpt = chain.signed_checkpoint()

    witness = Witness(generate_keypair(), log_public_key=log_key.public_key_hex)
    with pytest.raises(WitnessRefusal, match="pinned log key"):
        witness.cosign(ckpt)


# --- reference HTTP witness ---


def test_witness_http_cosign_and_refusal():
    starlette = pytest.importorskip("starlette")
    from starlette.testclient import TestClient

    assert starlette  # silence unused
    log_key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=log_key)
    _grow(chain, start=0, n=3)
    ckpt_a = chain.signed_checkpoint()

    witness = Witness(generate_keypair(), log_public_key=log_key.public_key_hex)
    client = TestClient(create_witness_app(witness))

    resp = client.post("/v1/witness/cosign", json={"checkpoint": ckpt_a})
    assert resp.status_code == 200
    assert resp.json()["cosigned"] is True

    # A same-size fork must be refused over HTTP with 409.
    chain_b = AuditChain.in_memory(signing_key=log_key)
    _grow(chain_b, start=100, n=3)
    resp2 = client.post(
        "/v1/witness/cosign", json={"checkpoint": chain_b.signed_checkpoint()}
    )
    assert resp2.status_code == 409
    assert resp2.json()["cosigned"] is False


def test_add_witness_cosignature_requires_allow_unsafe():
    chain = AuditChain.in_memory(signing_key=generate_keypair())
    _grow(chain, start=0, n=2)
    ckpt = chain.signed_checkpoint()
    with pytest.raises(ValueError, match="allow_unsafe"):
        add_witness_cosignature(ckpt, generate_keypair())


def test_witness_http_requires_api_key_when_configured(monkeypatch):
    starlette = pytest.importorskip("starlette")
    from starlette.testclient import TestClient

    assert starlette  # silence unused
    log_key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=log_key)
    _grow(chain, start=0, n=2)
    ckpt = chain.signed_checkpoint()

    witness = Witness(generate_keypair(), log_public_key=log_key.public_key_hex)
    monkeypatch.setenv("AGENT_RECEIPTS_WITNESS_API_KEY", "witness-secret")
    client = TestClient(create_witness_app(witness))

    denied = client.post("/v1/witness/cosign", json={"checkpoint": ckpt})
    assert denied.status_code == 401

    allowed = client.post(
        "/v1/witness/cosign",
        json={"checkpoint": ckpt},
        headers={"X-API-Key": "witness-secret"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["cosigned"] is True
