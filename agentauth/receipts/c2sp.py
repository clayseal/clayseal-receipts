"""C2SP checkpoint (signed-note) format for the audit log.

Our internal transparency log (see :mod:`agentauth.receipts.audit`) uses an RFC 6962
*tree structure* but a non-standard leaf/node hashing (hex concatenation, no domain
separation). That is fine for our own verifier, but it is **not** what the witness /
monitor ecosystem speaks. This module emits a standards-correct view:

- a true **RFC 6962 Merkle Tree Hash** over the record leaves (domain-separated raw bytes:
  leaf = SHA-256(0x00 || entry), node = SHA-256(0x01 || left || right)), and
- the **C2SP signed-note checkpoint** serialization (origin / size / base64 root + an
  Ed25519 note signature), so our checkpoints can be co-signed and audited by existing
  note-format witnesses.

Spec: <https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md> and
<https://github.com/C2SP/C2SP/blob/main/signed-note.md>. Fully migrating our inclusion /
consistency proofs to RFC 6962 / COSE Receipts is the larger SCITT alignment (finding A in
docs/combined_corpus_sota_review.md); this is the self-contained checkpoint win.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_NOTE_SIG_PREFIX = "— "  # em dash + space


# --------------------------------------------------------------------------- #
# RFC 6962 Merkle Tree Hash (raw bytes, domain-separated) -- §2.1.
# --------------------------------------------------------------------------- #
def rfc6962_leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def rfc6962_root(entries: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over raw leaf entries (empty tree -> SHA-256 of empty)."""
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return rfc6962_leaf_hash(entries[0])
    k = _largest_power_of_two_below(len(entries))
    return _node_hash(rfc6962_root(entries[:k]), rfc6962_root(entries[k:]))


def rfc6962_inclusion_path(index: int, entries: list[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.1 audit path for leaf ``index``."""
    n = len(entries)
    if not 0 <= index < n:
        raise IndexError(f"leaf index {index} out of range for {n} entries")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return rfc6962_inclusion_path(index, entries[:k]) + [rfc6962_root(entries[k:])]
    return rfc6962_inclusion_path(index - k, entries[k:]) + [rfc6962_root(entries[:k])]


def rfc6962_root_from_path(
    leaf_hash: bytes, index: int, tree_size: int, path: list[bytes]
) -> bytes | None:
    """Reconstruct the RFC 6962 root from a leaf hash + audit path (None if malformed)."""
    if not 0 <= index < tree_size:
        return None

    def recon(idx: int, size: int, p: list[bytes]) -> bytes | None:
        if size == 1:
            return leaf_hash if not p else None
        if not p:
            return None
        k = _largest_power_of_two_below(size)
        sib = p[-1]
        if idx < k:
            left = recon(idx, k, p[:-1])
            return _node_hash(left, sib) if left is not None else None
        right = recon(idx - k, size - k, p[:-1])
        return _node_hash(sib, right) if right is not None else None

    return recon(index, tree_size, list(path))


def rfc6962_verify_inclusion(
    leaf_hash: bytes, index: int, tree_size: int, path: list[bytes], root: bytes
) -> bool:
    """Reconstruct the RFC 6962 root from a leaf hash + audit path and compare."""
    return rfc6962_root_from_path(leaf_hash, index, tree_size, list(path)) == root


def _subproof(m: int, entries: list[bytes], b: bool) -> list[bytes]:
    """RFC 6962 §2.1.2 SUBPROOF over ``entries`` for the first ``m`` of them."""
    n = len(entries)
    if m == n:
        return [] if b else [rfc6962_root(entries)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, entries[:k], b) + [rfc6962_root(entries[k:])]
    return _subproof(m - k, entries[k:], False) + [rfc6962_root(entries[:k])]


def rfc6962_consistency_path(old_size: int, entries: list[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.2 consistency proof between the first ``old_size`` leaves and all."""
    new_size = len(entries)
    if not 0 <= old_size <= new_size:
        raise ValueError(f"old_size {old_size} out of range for {new_size} entries")
    if old_size == 0 or old_size == new_size:
        return []
    return _subproof(old_size, entries, True)


def rfc6962_consistency_roots(
    old_size: int, new_size: int, path: list[bytes], old_root: bytes
) -> tuple[bytes, bytes] | None:
    """Reconstruct (old_root, new_root) from a consistency proof (RFC 6962 §2.1.2).

    Mirrors the validated internal algorithm in :mod:`agentauth.receipts.audit` but with
    domain-separated hashing. Returns the reconstructed pair, or None if malformed.
    """
    if old_size == 0 or old_size > new_size:
        return None
    if old_size == new_size:
        return (old_root, old_root) if not path else None
    nodes = list(path)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if old_size & (old_size - 1) == 0:  # power of two
        fr = sr = old_root
    else:
        if not nodes:
            return None
        fr = sr = nodes.pop(0)
    for c in nodes:
        if sn == 0:
            return None
        if (fn & 1) or fn == sn:
            fr = _node_hash(c, fr)
            sr = _node_hash(c, sr)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return None
    return fr, sr


# --------------------------------------------------------------------------- #
# C2SP signed-note format.
# --------------------------------------------------------------------------- #
def note_key_id(name: str, public_key: Ed25519PublicKey) -> bytes:
    """C2SP/Go note key id: first 4 bytes of SHA-256(name || 0x0A || 0x01 || pubkey)."""
    raw = public_key.public_bytes_raw()
    return hashlib.sha256(name.encode() + b"\x0a" + b"\x01" + raw).digest()[:4]


def checkpoint_body(
    origin: str, tree_size: int, root: bytes, extensions: list[str] | None = None
) -> str:
    """The C2SP checkpoint note text (ends in newline). Lines: origin / size / b64(root)."""
    if not origin or " " in origin or "+" in origin:
        raise ValueError("origin must be non-empty with no spaces or '+'")
    lines = [origin, str(tree_size), base64.standard_b64encode(root).decode()]
    for ext in extensions or []:
        if not ext:
            raise ValueError("extension lines must be non-empty")
        lines.append(ext)
    return "\n".join(lines) + "\n"


def sign_note(body: str, name: str, private_key: Ed25519PrivateKey) -> str:
    """Produce a signed note: body, a blank line, then one Ed25519 signature line."""
    key_id = note_key_id(name, private_key.public_key())
    signature = private_key.sign(body.encode())
    encoded = base64.standard_b64encode(key_id + signature).decode()
    return f"{body}\n{_NOTE_SIG_PREFIX}{name} {encoded}\n"


def verify_note(note: str, name: str, public_key: Ed25519PublicKey) -> bool:
    """Verify that ``note`` carries a valid Ed25519 signature by ``name``/``public_key``.

    The signature covers only the note body (up to, and excluding, the blank line).
    """
    sep = "\n\n"
    idx = note.find(sep)
    if idx == -1:
        return False
    body = note[: idx + 1]  # include the body's trailing newline
    sig_block = note[idx + len(sep):]
    want_id = note_key_id(name, public_key)
    line_prefix = f"{_NOTE_SIG_PREFIX}{name} "
    for line in sig_block.splitlines():
        if not line.startswith(line_prefix):
            continue
        try:
            raw = base64.standard_b64decode(line[len(line_prefix):])
        except (ValueError, Exception):  # noqa: BLE001
            continue
        if len(raw) != 4 + 64 or raw[:4] != want_id:
            continue
        try:
            public_key.verify(raw[4:], body.encode())
            return True
        except Exception:  # noqa: BLE001 - InvalidSignature and friends
            continue
    return False
