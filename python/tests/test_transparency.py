"""Transparency-log tests: RFC 6962 Merkle inclusion + consistency proofs (SOTA-1)."""

from __future__ import annotations

import argparse
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from agentauth.receipts.audit import (
    GENESIS,
    AuditChain,
    consistency_path,
    inclusion_path,
    merkle_root,
    root_from_inclusion_path,
    root_pair_from_consistency_path,
)
from agentauth.receipts.cli import cmd_audit_consistency
from agentauth.core.hash_util import sha256_hex
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.core.signing import generate_keypair, load_or_create_key
from agentauth.receipts.witness import Witness


def _leaves(n: int) -> list[str]:
    return [sha256_hex(f"leaf-{i}".encode()) for i in range(n)]


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


def _chain(n: int) -> AuditChain:
    chain = AuditChain.in_memory()
    for i in range(n):
        chain.append(_proof(i), action=f"action-{i}")
    return chain


# --- pure Merkle math (broad sweep over tree sizes) ---


def test_inclusion_proof_accepts_every_leaf():
    for n in range(1, 18):
        leaves = _leaves(n)
        root = merkle_root(leaves)
        for i in range(n):
            path = inclusion_path(i, leaves)
            assert root_from_inclusion_path(i, n, leaves[i], path) == root


def test_inclusion_proof_rejects_wrong_leaf_and_tampered_path():
    leaves = _leaves(11)
    root = merkle_root(leaves)
    path = inclusion_path(4, leaves)
    assert root_from_inclusion_path(4, 11, sha256_hex(b"evil"), path) != root
    tampered = list(path)
    tampered[0] = sha256_hex(b"x" + tampered[0].encode())
    assert root_from_inclusion_path(4, 11, leaves[4], tampered) != root


def test_consistency_proof_accepts_all_prefixes():
    for n in range(1, 18):
        leaves = _leaves(n)
        new_root = merkle_root(leaves)
        for m in range(1, n + 1):
            old_root = merkle_root(leaves[:m])
            path = consistency_path(m, leaves)
            assert root_pair_from_consistency_path(m, n, path, old_root) == (
                old_root,
                new_root,
            )


def test_consistency_proof_rejects_rewritten_history():
    # Rewriting any historical leaf must break consistency against the
    # originally committed old root: the attacker's new root won't reconstruct.
    for n in range(2, 16):
        leaves = _leaves(n)
        for m in range(1, n):
            old_root = merkle_root(leaves[:m])
            for j in range(m):
                rewritten = list(leaves)
                rewritten[j] = sha256_hex(f"rewrite-{j}".encode())
                new_root = merkle_root(rewritten)
                path = consistency_path(m, rewritten)
                roots = root_pair_from_consistency_path(m, n, path, old_root)
                assert roots is None or roots != (old_root, new_root)


# --- AuditChain integration against signed checkpoints ---


def test_chain_inclusion_against_checkpoint():
    chain = _chain(7)
    checkpoint = chain.signed_checkpoint()
    for record in chain.iter_records():
        proof = chain.inclusion_proof(record.record_hash)
        assert AuditChain.verify_inclusion(record.record_hash, proof, checkpoint)


def test_chain_inclusion_rejects_foreign_record():
    chain = _chain(5)
    checkpoint = chain.signed_checkpoint()
    proof = chain.inclusion_proof(chain.iter_records()[2].record_hash)
    # A different record hash with the same proof must not verify.
    assert not AuditChain.verify_inclusion(sha256_hex(b"not-in-log"), proof, checkpoint)


def test_chain_inclusion_rejects_stale_checkpoint():
    chain = _chain(4)
    record = chain.iter_records()[1]
    proof = chain.inclusion_proof(record.record_hash)
    old_checkpoint = chain.signed_checkpoint()
    chain.append(_proof(100), action="action-late")
    # Proof was built at size 4; the size-5 checkpoint must reject it (tree_size mismatch).
    new_checkpoint = chain.signed_checkpoint()
    assert not AuditChain.verify_inclusion(record.record_hash, proof, new_checkpoint)
    # And it still verifies against the matching older checkpoint.
    assert AuditChain.verify_inclusion(record.record_hash, proof, old_checkpoint)


def test_chain_consistency_accepts_append_only_growth():
    chain = _chain(3)
    old_checkpoint = chain.signed_checkpoint()
    for i in range(4):
        chain.append(_proof(10 + i), action=f"more-{i}")
    new_checkpoint = chain.signed_checkpoint()
    proof = chain.consistency_proof(old_checkpoint["count"], new_checkpoint["count"])
    assert AuditChain.verify_consistency(old_checkpoint, new_checkpoint, proof)


def test_chain_consistency_rejects_history_rewrite():
    chain = _chain(3)
    old_checkpoint = chain.signed_checkpoint()
    for i in range(3):
        chain.append(_proof(10 + i), action=f"more-{i}")
    new_checkpoint = chain.signed_checkpoint()
    proof = chain.consistency_proof(old_checkpoint["count"], new_checkpoint["count"])
    # Tamper with the earlier committed root -> proof must not validate.
    forged_old = dict(old_checkpoint, merkle_root=sha256_hex(b"forged"))
    assert not AuditChain.verify_consistency(forged_old, new_checkpoint, proof)
    # Tamper with a proof node -> must not validate.
    bad_proof = dict(proof, path=[sha256_hex(b"bad"), *proof["path"][1:]])
    if proof["path"]:
        assert not AuditChain.verify_consistency(old_checkpoint, new_checkpoint, bad_proof)


def test_execution_proof_hash_binds_context_and_certificate():
    from dataclasses import replace

    from agentauth.receipts.audit import execution_proof_hash

    base = _proof(0)
    other_context = replace(base, context_hash="ctx-other")
    other_cert = replace(base, certificate_ref="cert-other")
    assert execution_proof_hash(base) != execution_proof_hash(other_context)
    assert execution_proof_hash(base) != execution_proof_hash(other_cert)


def test_audit_records_differ_when_proof_commitments_differ():
    from dataclasses import replace

    chain = AuditChain.in_memory()
    first = chain.append(_proof(0), action="act0")
    second = chain.append(
        replace(_proof(0), context_hash="different-context"),
        action="act0",
    )
    assert first.execution_proof_hash != second.execution_proof_hash
    assert first.record_hash != second.record_hash
    chain.verify_chain()


def test_file_audit_chain_serializes_concurrent_appenders(tmp_path):
    db = tmp_path / "audit.sqlite"
    AuditChain(db)

    def append_one(i: int) -> int:
        chain = AuditChain(db)
        record = chain.append(_proof(i), action=f"act-{i}")
        return record.seq

    with ThreadPoolExecutor(max_workers=8) as pool:
        seqs = list(pool.map(append_one, range(32)))

    chain = AuditChain(db)
    assert sorted(seqs) == list(range(1, 33))
    assert len(chain) == 32
    records = chain.iter_records()
    assert records[0].prev_hash == GENESIS
    for prev, current in zip(records, records[1:]):
        assert current.prev_hash == prev.record_hash
    chain.verify_chain()


def test_audit_consistency_cli_exits_nonzero_without_old_checkpoint(tmp_path):
    db = tmp_path / "audit.sqlite"
    chain = AuditChain(db)
    chain.append(_proof(0), action="seed")
    args = argparse.Namespace(audit_db=str(db), old_size=0, new_size=None, old_checkpoint=None)
    assert cmd_audit_consistency(args) == 2


def test_audit_consistency_cli_enforces_trusted_checkpoint(tmp_path, monkeypatch):
    key_path = tmp_path / "audit-signing.pem"
    log_key = load_or_create_key(key_path)
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_AUDIT_LOG_PUBLIC_KEYS", log_key.public_key_hex)

    db = tmp_path / "audit.sqlite"
    chain = AuditChain(db, signing_key=log_key)
    chain.append(_proof(0), action="seed")
    old_checkpoint = chain.signed_checkpoint()
    chain.append(_proof(1), action="more")
    old_path = tmp_path / "old.json"
    old_path.write_text(json.dumps(old_checkpoint), encoding="utf-8")

    args = argparse.Namespace(
        audit_db=str(db),
        old_size=old_checkpoint["count"],
        new_size=None,
        old_checkpoint=str(old_path),
        signing_key=key_path,
    )
    assert cmd_audit_consistency(args) == 0

    bad_key = generate_keypair()
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_AUDIT_LOG_PUBLIC_KEYS", bad_key.public_key_hex)
    assert cmd_audit_consistency(args) == 1


def test_chain_consistency_rejects_untrusted_or_unsigned_checkpoints():
    log_key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=log_key)

    def grow(start: int, n: int) -> None:
        for i in range(n):
            chain.append(_proof(start + i), action=f"a-{start + i}")

    grow(0, 3)
    old_checkpoint = chain.signed_checkpoint()
    grow(10, 2)
    new_checkpoint = chain.signed_checkpoint()
    proof = chain.consistency_proof(old_checkpoint["count"], new_checkpoint["count"])

    assert AuditChain.verify_consistency(
        old_checkpoint,
        new_checkpoint,
        proof,
        trusted_log_public_keys={log_key.public_key_hex},
    )

    unsigned_new = {k: v for k, v in new_checkpoint.items() if k != "signature"}
    assert not AuditChain.verify_consistency(
        old_checkpoint,
        unsigned_new,
        proof,
        trusted_log_public_keys={log_key.public_key_hex},
    )


def test_chain_consistency_requires_witness_quorum():
    log_key = generate_keypair()
    witness_key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=log_key)
    for i in range(3):
        chain.append(_proof(i), action=f"seed-{i}")
    old_checkpoint = chain.signed_checkpoint()
    witness = Witness(witness_key, log_public_key=log_key.public_key_hex)
    witness.cosign(old_checkpoint)

    for i in range(3):
        chain.append(_proof(10 + i), action=f"more-{i}")
    new_checkpoint = chain.signed_checkpoint()
    proof = chain.consistency_proof(old_checkpoint["count"], new_checkpoint["count"])
    witness.cosign(new_checkpoint, consistency_proof=proof)

    assert AuditChain.verify_consistency(
        old_checkpoint,
        new_checkpoint,
        proof,
        trusted_log_public_keys={log_key.public_key_hex},
        required_witnesses=1,
        trusted_witness_keys={witness_key.public_key_hex},
    )

    assert not AuditChain.verify_consistency(
        old_checkpoint,
        new_checkpoint,
        proof,
        trusted_log_public_keys={log_key.public_key_hex},
        required_witnesses=2,
        trusted_witness_keys={witness_key.public_key_hex},
    )


def test_audit_consistency_cli_rejects_unsigned_new_checkpoint_under_trust(tmp_path, monkeypatch):
    log_key = generate_keypair()
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_AUDIT_LOG_PUBLIC_KEYS", log_key.public_key_hex)

    db = tmp_path / "audit.sqlite"
    chain = AuditChain(db, signing_key=log_key)
    chain.append(_proof(0), action="seed")
    old_checkpoint = chain.signed_checkpoint()
    chain.append(_proof(1), action="more")
    old_path = tmp_path / "old.json"
    old_path.write_text(json.dumps(old_checkpoint), encoding="utf-8")

    args = argparse.Namespace(
        audit_db=str(db),
        old_size=old_checkpoint["count"],
        new_size=None,
        old_checkpoint=str(old_path),
        signing_key=None,
    )
    assert cmd_audit_consistency(args) == 1
