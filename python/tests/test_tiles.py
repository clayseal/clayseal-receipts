"""Tile-based static log export (C2SP tlog-tiles, SOTA-14)."""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone

from agentauth.receipts import c2sp, tiles
from agentauth.receipts.audit import AuditChain
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.core.signing import generate_keypair


def _entries(n: int) -> list[bytes]:
    return [hashlib.sha256(f"e{i}".encode()).digest() for i in range(n)]


# --- path encoding --------------------------------------------------------- #


def test_index_path_encoding():
    assert tiles._index_path(0) == "000"
    assert tiles._index_path(67) == "067"
    assert tiles._index_path(1234067) == "x001/x234/067"
    assert tiles.tile_path(0, 1, 44) == "tile/0/001.p/44"
    assert tiles.tile_path(1, 0) == "tile/1/000"


# --- hash tiles ------------------------------------------------------------ #


def test_full_and_partial_tile_sizes_and_paths():
    entries = _entries(300)  # level0: 1 full tile + 1 partial(44); level1: partial(2)
    t = tiles.build_hash_tiles(entries)
    assert len(t["tile/0/000"]) == 256 * 32  # full tile = 8192 bytes
    assert "tile/0/001.p/44" in t and len(t["tile/0/001.p/44"]) == 44 * 32
    assert "tile/1/000.p/2" in t and len(t["tile/1/000.p/2"]) == 2 * 32


def test_level0_tile_holds_leaf_hashes():
    entries = _entries(10)
    t = tiles.build_hash_tiles(entries)
    tile0 = t["tile/0/000.p/10"]
    for i in range(10):
        # Independent recompute of the RFC 6962 leaf hash.
        assert tile0[i * 32 : (i + 1) * 32] == c2sp.rfc6962_leaf_hash(entries[i])


def test_level1_node_is_root_of_its_256_leaf_span():
    entries = _entries(300)
    t = tiles.build_hash_tiles(entries)
    node0 = t["tile/1/000.p/2"][0:32]
    assert node0 == c2sp.rfc6962_root(entries[0:256])  # independent


# --- entry bundles --------------------------------------------------------- #


def test_entry_bundle_roundtrips():
    entries = _entries(300)
    b = tiles.build_entry_bundles(entries)
    recovered = tiles.parse_entry_bundle(b["tile/entries/000"]) + tiles.parse_entry_bundle(
        b["tile/entries/001.p/44"]
    )
    assert recovered == entries


# --- full static log + AuditChain integration ------------------------------ #


def _chain(n: int) -> AuditChain:
    chain = AuditChain.in_memory(signing_key=generate_keypair())
    for i in range(n):
        chain.append(
            ExecutionProof(
                proof_id=uuid.uuid4(),
                agent_id=uuid.uuid4(),
                certificate_ref="c",
                policy_commitment="pc",
                context_hash="ch",
                output_hash=f"oh{i}",
                attestation_path=AttestationPath.SHADOW,
                policy_satisfied=True,
                decision_outcome=DecisionOutcome.ALLOW,
                authority_version=1,
                session_id=None,
                created_at=datetime.now(timezone.utc),
            ),
            action=f"a{i}",
        )
    return chain


def test_static_log_export_and_checkpoint_consistency():
    chain = _chain(5)
    files = chain.static_log_tiles("agent-receipts.local/audit")

    # The checkpoint is present, signed, and verifiable.
    note = files["checkpoint"].decode()
    assert c2sp.verify_note(note, "agent-receipts.local/audit", chain.signing_key.public_key)

    # Tiles reconstruct the checkpoint root: rebuild leaf hashes from the entry
    # bundle and fold them into the RFC 6962 root, independent of the hash tiles.
    entries = tiles.parse_entry_bundle(files["tile/entries/000.p/5"])
    leaves_root = c2sp.rfc6962_root(entries)
    checkpoint_root = base64.standard_b64decode(note.split("\n")[2])
    assert leaves_root == checkpoint_root

    # Level-0 tile leaf hashes match those entries too.
    tile0 = files["tile/0/000.p/5"]
    for i, e in enumerate(entries):
        assert tile0[i * 32 : (i + 1) * 32] == c2sp.rfc6962_leaf_hash(e)


def test_empty_log_has_no_tiles():
    assert tiles.build_hash_tiles([]) == {}


def test_write_load_and_verify_leaf_from_static_log(tmp_path):
    chain = _chain(5)
    files = chain.static_log_tiles("agent-receipts.local/audit")
    out = tmp_path / "log"
    tiles.write_static_log(files, out)
    loaded = tiles.load_static_log(out)
    record = chain.iter_records()[2]
    leaf = bytes.fromhex(record.record_hash)
    assert tiles.verify_leaf_in_static_log(loaded, leaf)
    assert not tiles.verify_leaf_in_static_log(loaded, b"\x01" * 32)


def test_large_log_tile_client_reconstructs_checkpoint_root():
    chain = _chain(300)
    files = chain.static_log_tiles("agent-receipts.local/audit")
    note = files["checkpoint"].decode()
    _size, checkpoint_root = tiles.checkpoint_root_from_note(note)
    entries = tiles.entries_from_static_log(files)
    assert len(entries) == 300
    assert c2sp.rfc6962_root(entries) == checkpoint_root
    leaf = bytes.fromhex(chain.iter_records()[150].record_hash)
    assert tiles.verify_leaf_in_static_log(files, leaf)
