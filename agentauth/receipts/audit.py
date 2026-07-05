from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from agentauth.core.hash_util import hash_canonical_json, sha256_hex
from agentauth.receipts.proof import ExecutionProof
from agentauth.receipts.revocation import SignerRevocationRegistry
from agentauth.core.signing import SigningKey
from agentauth.core.signing import verify as verify_signature

GENESIS = sha256_hex(b"agent-receipts-genesis")
TRUSTED_AUDIT_LOG_PUBLIC_KEYS_ENV = "AGENT_RECEIPTS_TRUSTED_AUDIT_LOG_PUBLIC_KEYS"
TRUSTED_AUDIT_LOG_KEY_IDS_ENV = "AGENT_RECEIPTS_TRUSTED_AUDIT_LOG_KEY_IDS"
TRUSTED_AUDIT_WITNESS_KEYS_ENV = "AGENT_RECEIPTS_TRUSTED_AUDIT_WITNESS_KEYS"
REQUIRED_AUDIT_WITNESSES_ENV = "AGENT_RECEIPTS_REQUIRED_AUDIT_WITNESSES"


def execution_proof_commitment(proof: ExecutionProof) -> dict[str, Any]:
    """Canonical execution-proof fields bound into each audit log leaf."""
    return {
        "proof_id": str(proof.proof_id),
        "agent_id": str(proof.agent_id),
        "certificate_ref": proof.certificate_ref,
        "policy_commitment": proof.policy_commitment,
        "context_hash": proof.context_hash,
        "output_hash": proof.output_hash,
        "attestation_path": proof.attestation_path.value,
        "policy_satisfied": proof.policy_satisfied,
        "decision_outcome": proof.decision_outcome.value,
        "authority_version": proof.authority_version,
        "session_id": proof.session_id,
        "created_at": proof.created_at.isoformat(),
        "obligations": list(proof.obligations),
        "bundle": proof.bundle.to_dict(),
    }


def execution_proof_hash(proof: ExecutionProof) -> str:
    """Hash of the full execution-proof commitment stored on each audit record."""
    return hash_canonical_json(execution_proof_commitment(proof))


def _hash_children(left: str, right: str) -> str:
    return sha256_hex((left + right).encode("utf-8"))


def _largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly less than ``n`` (RFC 6962 split point, n >= 2)."""
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def merkle_root(leaves: list[str]) -> str:
    """RFC 6962 Merkle Tree Hash over record hashes (empty → GENESIS).

    Unlike a Bitcoin-style duplicate-last tree, the RFC 6962 structure splits at
    the largest power of two below ``n``; this is what makes the inclusion and
    consistency proofs below standard and append-only verifiable.
    """
    if not leaves:
        return GENESIS
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_below(n)
    return _hash_children(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_path(index: int, leaves: list[str]) -> list[str]:
    """RFC 6962 §2.1.1 audit path: sibling hashes from leaf ``index`` up to the root."""
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf index {index} out of range for {len(leaves)} leaves")
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return inclusion_path(index, leaves[:k]) + [merkle_root(leaves[k:])]
    return inclusion_path(index - k, leaves[k:]) + [merkle_root(leaves[:k])]


def root_from_inclusion_path(
    index: int, tree_size: int, leaf_hash: str, path: list[str]
) -> str | None:
    """Reconstruct the Merkle root from a leaf and its audit path (verifier side).

    Mirrors :func:`inclusion_path`: the sibling appended last at each level is
    consumed first. Returns ``None`` if the proof is malformed for the claimed
    ``index``/``tree_size`` (e.g. wrong length).
    """
    if not 0 <= index < tree_size:
        return None
    if tree_size == 1:
        return leaf_hash if not path else None
    if not path:
        return None
    k = _largest_power_of_two_below(tree_size)
    sibling = path[-1]
    if index < k:
        left = root_from_inclusion_path(index, k, leaf_hash, path[:-1])
        return _hash_children(left, sibling) if left is not None else None
    right = root_from_inclusion_path(index - k, tree_size - k, leaf_hash, path[:-1])
    return _hash_children(sibling, right) if right is not None else None


def _subproof(m: int, leaves: list[str], b: bool) -> list[str]:
    """RFC 6962 §2.1.2 SUBPROOF over ``leaves`` for the first ``m`` of them."""
    n = len(leaves)
    if m == n:
        return [] if b else [merkle_root(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


def consistency_path(old_size: int, leaves: list[str]) -> list[str]:
    """RFC 6962 §2.1.2 consistency proof between the first ``old_size`` leaves and all."""
    new_size = len(leaves)
    if not 0 <= old_size <= new_size:
        raise ValueError(f"old_size {old_size} out of range for {new_size} leaves")
    if old_size == 0 or old_size == new_size:
        return []
    return _subproof(old_size, leaves, True)


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def root_pair_from_consistency_path(
    old_size: int,
    new_size: int,
    path: list[str],
    old_root: str,
) -> tuple[str, str] | None:
    """Reconstruct (old_root, new_root) from a consistency proof (RFC 6962 §2.1.2).

    ``old_root`` is supplied because, when ``old_size`` is a power of two, the old
    tree is a single complete subtree whose hash is not carried in the proof.
    Returns the reconstructed pair, or ``None`` if the proof is malformed.
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

    if _is_power_of_two(old_size):
        fr = sr = old_root
    else:
        if not nodes:
            return None
        fr = sr = nodes.pop(0)

    for c in nodes:
        if sn == 0:
            return None
        if (fn & 1) or fn == sn:
            fr = _hash_children(c, fr)
            sr = _hash_children(c, sr)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _hash_children(sr, c)
        fn >>= 1
        sn >>= 1

    if sn != 0:
        return None
    return fr, sr


_CHECKPOINT_CORE_FIELDS = ("count", "tip_hash", "merkle_root", "genesis")


def checkpoint_body(checkpoint: dict[str, Any]) -> dict[str, Any]:
    """The signed core of a checkpoint (no signatures) — what log + witnesses sign over."""
    return {field: checkpoint.get(field) for field in _CHECKPOINT_CORE_FIELDS}


def _split_env_list(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def trusted_audit_log_policy_from_env() -> dict[str, set[str]]:
    return {
        "public_keys": _split_env_list(TRUSTED_AUDIT_LOG_PUBLIC_KEYS_ENV),
        "key_ids": _split_env_list(TRUSTED_AUDIT_LOG_KEY_IDS_ENV),
    }


def trusted_audit_witness_keys_from_env() -> set[str]:
    return _split_env_list(TRUSTED_AUDIT_WITNESS_KEYS_ENV)


def required_audit_witnesses_from_env() -> int:
    raw = os.getenv(REQUIRED_AUDIT_WITNESSES_ENV, "").strip()
    if not raw:
        return 0
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{REQUIRED_AUDIT_WITNESSES_ENV} must be an integer") from exc
    if value < 0:
        raise ValueError(f"{REQUIRED_AUDIT_WITNESSES_ENV} must be >= 0")
    return value


def verify_signed_checkpoint(
    checkpoint: dict[str, Any],
    *,
    trusted_public_keys: set[str] | None = None,
    trusted_key_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Verify checkpoint signature presence, crypto validity, and signer trust."""
    signature = checkpoint.get("signature")
    trusted_public_keys = trusted_public_keys or set()
    trusted_key_ids = trusted_key_ids or set()
    trust_configured = bool(trusted_public_keys or trusted_key_ids)
    if signature is None:
        return {
            "valid": False,
            "signed": False,
            "cryptographically_valid": False,
            "trust_configured": trust_configured,
            "trusted": False,
            "reasons": ["audit checkpoint is unsigned"],
        }
    body = checkpoint_body(checkpoint)
    cryptographically_valid = verify_signature(body, signature)
    if not cryptographically_valid:
        return {
            "valid": False,
            "signed": True,
            "cryptographically_valid": False,
            "trust_configured": trust_configured,
            "trusted": False,
            "reasons": ["audit checkpoint signature is invalid"],
        }
    if not trust_configured:
        return {
            "valid": False,
            "signed": True,
            "cryptographically_valid": True,
            "trust_configured": False,
            "trusted": False,
            "reasons": ["no trusted audit log policy configured"],
        }
    public_key = signature.get("public_key")
    key_id = signature.get("key_id")
    trusted = False
    if public_key and public_key in trusted_public_keys:
        trusted = True
    if key_id and key_id in trusted_key_ids:
        trusted = True
    return {
        "valid": trusted,
        "signed": True,
        "cryptographically_valid": True,
        "trust_configured": True,
        "trusted": trusted,
        "reasons": [] if trusted else ["untrusted audit checkpoint signer"],
    }


def checkpoint_trust_issues(
    checkpoint: dict[str, Any],
    *,
    trusted_public_keys: set[str] | None = None,
    trusted_key_ids: set[str] | None = None,
    required_witnesses: int | None = None,
    trusted_witness_keys: set[str] | None = None,
    revocation_registry: SignerRevocationRegistry | None = None,
) -> list[str]:
    """Verify signer trust and optional witness quorum for a portable checkpoint."""
    log_policy = {
        "public_keys": trusted_public_keys,
        "key_ids": trusted_key_ids,
    }
    if log_policy["public_keys"] is None or log_policy["key_ids"] is None:
        env_policy = trusted_audit_log_policy_from_env()
        if log_policy["public_keys"] is None:
            log_policy["public_keys"] = env_policy["public_keys"]
        if log_policy["key_ids"] is None:
            log_policy["key_ids"] = env_policy["key_ids"]

    if not (log_policy["public_keys"] or log_policy["key_ids"]):
        return []

    issues: list[str] = []
    check = verify_signed_checkpoint(
        checkpoint,
        trusted_public_keys=log_policy["public_keys"],
        trusted_key_ids=log_policy["key_ids"],
    )
    if not check.get("valid"):
        issues.extend(check.get("reasons", ["audit checkpoint trust verification failed"]))

    if revocation_registry is not None:
        issues.extend(revocation_registry.checkpoint_revocation_issues(checkpoint))

    if required_witnesses is None:
        try:
            required_witnesses = required_audit_witnesses_from_env()
        except ValueError as exc:
            issues.append(str(exc))
            required_witnesses = 0
    if required_witnesses > 0:
        trusted_witnesses = (
            trusted_witness_keys
            if trusted_witness_keys is not None
            else trusted_audit_witness_keys_from_env()
        )
        witness_count = count_valid_witness_cosignatures(
            checkpoint,
            trusted_keys=trusted_witnesses,
        )
        if witness_count < required_witnesses:
            issues.append(
                "audit checkpoint does not meet witness quorum "
                f"({witness_count} < {required_witnesses})"
            )
    return issues


def count_valid_witness_cosignatures(
    checkpoint: dict[str, Any], *, trusted_keys: set[str] | None = None
) -> int:
    """Count distinct, valid external witness co-signatures over the checkpoint core.

    Restrict to ``trusted_keys`` (hex public keys) to count only witnesses a consumer
    actually trusts; duplicate keys are counted once.
    """
    body = checkpoint_body(checkpoint)
    seen: set[str] = set()
    for cosig in checkpoint.get("witness_cosignatures", []):
        public_key = cosig.get("public_key")
        if public_key is None or public_key in seen:
            continue
        if trusted_keys is not None and public_key not in trusted_keys:
            continue
        if verify_signature(body, cosig):
            seen.add(public_key)
    return len(seen)


@dataclass
class AuditRecord:
    seq: int
    proof_id: UUID
    execution_proof_hash: str
    action: str
    authorization_context: dict[str, Any]
    created_at: datetime
    prev_hash: str
    record_hash: str
    signature: dict[str, str] | None = None


class AuditChain:
    """Append-only hash-chained audit log (SQLite)."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        signing_key: SigningKey | None = None,
        revocation_registry: SignerRevocationRegistry | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.signing_key = signing_key
        self.revocation_registry = revocation_registry
        self._lock = threading.RLock()
        if str(db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._configure_connection()
        self._migrate()

    @classmethod
    def in_memory(
        cls,
        *,
        signing_key: SigningKey | None = None,
        revocation_registry: SignerRevocationRegistry | None = None,
    ) -> AuditChain:
        chain = cls(
            ":memory:",
            signing_key=signing_key,
            revocation_registry=revocation_registry,
        )
        return chain

    def _migrate(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_records (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    proof_id TEXT NOT NULL,
                    execution_proof_hash TEXT NOT NULL,
                    action TEXT NOT NULL,
                    authorization_context TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    signature TEXT
                )
                """
            )
            # Additive migration for pre-existing chains created before signatures.
            cols = {row[1] for row in self._conn.execute("PRAGMA table_info(audit_records)")}
            if "signature" not in cols:
                self._conn.execute("ALTER TABLE audit_records ADD COLUMN signature TEXT")

    def _tip_hash(self) -> str:
        row = self._conn.execute(
            "SELECT record_hash FROM audit_records ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS

    def _configure_connection(self) -> None:
        self._conn.execute("PRAGMA busy_timeout=30000")
        if str(self.db_path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")

    def append(
        self,
        proof: ExecutionProof,
        action: str,
        authorization_context: dict[str, Any] | None = None,
    ) -> AuditRecord:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                prev_hash = self._tip_hash()
                ctx = authorization_context or {}
                proof_hash = execution_proof_hash(proof)
                created_at = datetime.now(timezone.utc)
                body = {
                    "proof_id": str(proof.proof_id),
                    "execution_proof_hash": proof_hash,
                    "action": action,
                    "authorization_context": ctx,
                    "created_at": created_at.isoformat(),
                    "prev_hash": prev_hash,
                }
                record_hash = hash_canonical_json(body)
                signature = (
                    self.signing_key.sign({"record_hash": record_hash})
                    if self.signing_key is not None
                    else None
                )
                record = AuditRecord(
                    seq=0,
                    proof_id=proof.proof_id,
                    execution_proof_hash=proof_hash,
                    action=action,
                    authorization_context=ctx,
                    created_at=created_at,
                    prev_hash=prev_hash,
                    record_hash=record_hash,
                    signature=signature,
                )
                payload = json.dumps(
                    {
                        **body,
                        "seq": None,
                        "record_hash": record_hash,
                    },
                    sort_keys=True,
                )
                cur = self._conn.execute(
                    """
                    INSERT INTO audit_records
                    (proof_id, execution_proof_hash, action, authorization_context,
                     created_at, prev_hash, record_hash, payload, signature)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(proof.proof_id),
                        proof_hash,
                        action,
                        json.dumps(ctx, sort_keys=True),
                        created_at.isoformat(),
                        prev_hash,
                        record_hash,
                        payload,
                        json.dumps(signature) if signature is not None else None,
                    ),
                )
            except Exception:
                self._conn.rollback()
                raise
            self._conn.commit()
            record.seq = int(cur.lastrowid)
            return record

    def iter_records(self) -> list[AuditRecord]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT seq, proof_id, execution_proof_hash, action, authorization_context,
                       created_at, prev_hash, record_hash, signature
                FROM audit_records ORDER BY seq ASC
                """
            ).fetchall()
        out: list[AuditRecord] = []
        for row in rows:
            ctx = json.loads(row[4])
            out.append(
                AuditRecord(
                    seq=int(row[0]),
                    proof_id=UUID(row[1]),
                    execution_proof_hash=row[2],
                    action=row[3],
                    authorization_context=ctx,
                    created_at=datetime.fromisoformat(row[5]),
                    prev_hash=row[6],
                    record_hash=row[7],
                    signature=json.loads(row[8]) if row[8] else None,
                )
            )
        return out

    def export_jsonl(self, path: str | Path) -> int:
        """Write all audit records as JSONL; returns record count."""
        records = self.iter_records()
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(audit_record_to_dict(rec), sort_keys=True))
                fh.write("\n")
        return len(records)

    def verify_chain(self) -> None:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, payload FROM audit_records ORDER BY seq ASC"
            ).fetchall()
        expected_prev = GENESIS
        for seq, payload in rows:
            data = json.loads(payload)
            if data["prev_hash"] != expected_prev:
                raise ValueError(f"chain break at seq {seq}: prev_hash mismatch")
            recomputed = hash_canonical_json(
                {
                    "proof_id": data["proof_id"],
                    "execution_proof_hash": data["execution_proof_hash"],
                    "action": data["action"],
                    "authorization_context": data["authorization_context"],
                    "created_at": data["created_at"],
                    "prev_hash": data["prev_hash"],
                }
            )
            if recomputed != data["record_hash"]:
                raise ValueError(f"chain break at seq {seq}: record_hash mismatch")
            expected_prev = data["record_hash"]

    def verify_signatures(
        self,
        *,
        expected_public_key: str | None = None,
        revocation_registry: SignerRevocationRegistry | None = None,
    ) -> None:
        """Verify every per-record signature against its record hash.

        Independent of ``verify_chain`` (hash linkage): this catches a full-chain
        rewrite where an attacker recomputes hashes consistently but cannot re-sign,
        and pins the signer when ``expected_public_key`` (hex) is given.

        When a :class:`~agentauth.receipts.revocation.SignerRevocationRegistry` is
        supplied (or configured on the chain), signatures at or after the key's
        revocation integrated-time are rejected.
        """
        registry = revocation_registry or self.revocation_registry
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, record_hash, signature FROM audit_records ORDER BY seq ASC"
            ).fetchall()
        for seq, record_hash, signature_json in rows:
            if signature_json is None:
                raise ValueError(f"record {seq} is unsigned")
            signature = json.loads(signature_json)
            if expected_public_key is not None and (
                signature.get("public_key") != expected_public_key
            ):
                raise ValueError(f"record {seq} signed by unexpected key")
            if registry is not None:
                for reason in registry.record_revocation_issues(
                    public_key_hex=signature.get("public_key"),
                    seq=int(seq),
                ):
                    raise ValueError(f"record {seq}: {reason}")
            if not verify_signature({"record_hash": record_hash}, signature):
                raise ValueError(f"record {seq}: invalid signature")

    def merkle_root(self) -> str:
        """Canonical **RFC 6962** Merkle root over all record hashes (hex).

        Domain-separated hashing shared with the C2SP checkpoint, SCITT receipts, and
        the tile export, so every view of the log commits to one root.
        """
        from agentauth.receipts import c2sp

        return c2sp.rfc6962_root(self._rfc6962_entries()).hex()

    def signed_checkpoint(self) -> dict[str, Any]:
        """Tamper-evidence anchor: count + tip + Merkle root, signed if a key is set.

        A signed checkpoint detects a full-chain rewrite (where an attacker recomputes
        every hash consistently): the rewritten Merkle root / tip will not match a
        previously issued, key-anchored checkpoint.
        """
        body = {
            "count": len(self),
            "tip_hash": self._tip_hash(),
            "merkle_root": self.merkle_root(),
            "genesis": GENESIS,
        }
        if self.signing_key is not None:
            body["signature"] = self.signing_key.sign(body)
        return body

    def verify_checkpoint(
        self,
        checkpoint: dict[str, Any],
        *,
        required_witnesses: int = 0,
        trusted_witness_keys: set[str] | None = None,
        revocation_registry: SignerRevocationRegistry | None = None,
    ) -> bool:
        """Verify a checkpoint still matches the chain, optionally requiring a witness quorum.

        With ``required_witnesses > 0`` the checkpoint must also carry at least that
        many distinct, valid external witness co-signatures (see :mod:`witness`), so a
        consumer can enforce "trust only logs ≥ K independent witnesses have endorsed."
        """
        current = {
            "count": len(self),
            "tip_hash": self._tip_hash(),
            "merkle_root": self.merkle_root(),
            "genesis": GENESIS,
        }
        for key in current:
            if checkpoint.get(key) != current[key]:
                return False
        signature = checkpoint.get("signature")
        if signature is not None and not verify_signature(current, signature):
            return False
        if required_witnesses > 0:
            witnesses = count_valid_witness_cosignatures(
                checkpoint, trusted_keys=trusted_witness_keys
            )
            if witnesses < required_witnesses:
                return False
        registry = revocation_registry or self.revocation_registry
        if registry is not None and registry.checkpoint_revocation_issues(checkpoint):
            return False
        return True

    def records_for_mandate_ref(self, ref: str) -> list[AuditRecord]:
        """Return audit records indexed by ``mandate_ref`` or ``token_ref`` (SOTA-16d)."""
        return [
            record
            for record in self.iter_records()
            if record.authorization_context.get("mandate_ref") == ref
            or record.authorization_context.get("token_ref") == ref
        ]

    def _record_hashes(self) -> list[str]:
        with self._lock:
            return [
                row[0]
                for row in self._conn.execute(
                    "SELECT record_hash FROM audit_records ORDER BY seq ASC"
                ).fetchall()
            ]

    def _rfc6962_entries(self) -> list[bytes]:
        """Audit leaves as raw bytes for standards-correct RFC 6962 hashing."""
        from binascii import unhexlify

        return [unhexlify(h) for h in self._record_hashes()]

    def c2sp_checkpoint(self, origin: str, *, key_name: str | None = None) -> str:
        """Serialize the current log head as a signed C2SP checkpoint note.

        Uses a true RFC 6962 Merkle root (domain-separated) and the Ed25519 note
        signature format so external witnesses/monitors can consume it. Requires a
        signing key. See :mod:`agentauth.receipts.c2sp`.
        """
        from agentauth.receipts import c2sp

        if self.signing_key is None:
            raise ValueError("c2sp_checkpoint requires a signing key on the chain")
        root = c2sp.rfc6962_root(self._rfc6962_entries())
        body = c2sp.checkpoint_body(origin, len(self), root)
        return c2sp.sign_note(body, key_name or origin, self.signing_key.private_key)

    def rfc6962_inclusion_proof(self, record_hash: str) -> dict[str, Any]:
        """RFC 6962 inclusion proof (raw-byte, domain-separated) for a record.

        Verifies against the root committed in :meth:`c2sp_checkpoint`, unlike the
        internal :meth:`inclusion_proof` which uses our non-standard hashing.
        """
        from agentauth.receipts import c2sp

        leaves = self._record_hashes()
        try:
            index = leaves.index(record_hash)
        except ValueError:
            raise KeyError(f"record_hash not in audit log: {record_hash}") from None
        entries = self._rfc6962_entries()
        path = c2sp.rfc6962_inclusion_path(index, entries)
        return {
            "leaf_index": index,
            "leaf_hash": c2sp.rfc6962_leaf_hash(entries[index]).hex(),
            "tree_size": len(leaves),
            "path": [p.hex() for p in path],
            "root": c2sp.rfc6962_root(entries).hex(),
        }

    def scitt_receipt(self, record_hash: str, *, service_id: str) -> bytes:
        """Issue a SCITT COSE Receipt proving a record is in this log (SOTA-11).

        The audit log acts as the Transparency Service: the receipt is a COSE_Sign1
        over the RFC 6962 root carrying the record's inclusion proof, signed by the
        log's key. Verify with ``scitt.verify_receipt(bytes.fromhex(record_hash), ...)``.
        """
        from agentauth.receipts import scitt

        if self.signing_key is None:
            raise ValueError("scitt_receipt requires a signing key on the chain")
        leaves = self._record_hashes()
        try:
            index = leaves.index(record_hash)
        except ValueError:
            raise KeyError(f"record_hash not in audit log: {record_hash}") from None
        return scitt.issue_inclusion_receipt(
            self._rfc6962_entries(), index, self.signing_key, service_id=service_id
        )

    def scitt_consistency_receipt(self, old_size: int, *, service_id: str) -> bytes:
        """Issue a SCITT COSE consistency Receipt (append-only proof) from ``old_size``."""
        from agentauth.receipts import scitt

        if self.signing_key is None:
            raise ValueError("scitt_consistency_receipt requires a signing key on the chain")
        return scitt.issue_consistency_receipt(
            self._rfc6962_entries(), old_size, self.signing_key, service_id=service_id
        )

    def static_log_tiles(self, origin: str, *, key_name: str | None = None) -> dict[str, bytes]:
        """Export the log as a C2SP tlog-tiles static file set (SOTA-14).

        Hash tiles + entry bundles over the RFC 6962 tree, plus the signed C2SP
        checkpoint at ``checkpoint`` — all static, cacheable assets. See :mod:`tiles`.
        """
        from agentauth.receipts import tiles

        checkpoint = self.c2sp_checkpoint(origin, key_name=key_name)
        return tiles.static_log(self._rfc6962_entries(), checkpoint)

    def inclusion_proof(self, record_hash: str) -> dict[str, Any]:
        """RFC 6962 inclusion proof that ``record_hash`` is a leaf of the current log."""
        return self.rfc6962_inclusion_proof(record_hash)

    @staticmethod
    def verify_inclusion(
        record_hash: str, proof: dict[str, Any], checkpoint: dict[str, Any]
    ) -> bool:
        """Confirm a record is in the log a checkpoint commits to, without rehashing the chain."""
        from agentauth.receipts import c2sp

        tree_size = proof.get("tree_size")
        if tree_size != checkpoint.get("count"):
            return False
        leaf = c2sp.rfc6962_leaf_hash(bytes.fromhex(record_hash))
        root = c2sp.rfc6962_root_from_path(
            leaf,
            int(proof["leaf_index"]),
            int(tree_size),
            [bytes.fromhex(p) for p in proof["path"]],
        )
        return root is not None and root.hex() == checkpoint.get("merkle_root")

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> dict[str, Any]:
        """Prove the log is an append-only extension from ``old_size`` to ``new_size``."""
        from agentauth.receipts import c2sp

        entries = self._rfc6962_entries()
        if new_size is None:
            new_size = len(entries)
        if not 0 <= old_size <= new_size <= len(entries):
            raise ValueError(
                f"sizes out of range: old={old_size} new={new_size} have={len(entries)}"
            )
        path = c2sp.rfc6962_consistency_path(old_size, entries[:new_size])
        return {
            "old_size": old_size,
            "new_size": new_size,
            "path": [p.hex() for p in path],
        }

    @staticmethod
    def verify_consistency(
        old_checkpoint: dict[str, Any],
        new_checkpoint: dict[str, Any],
        proof: dict[str, Any],
        *,
        trusted_log_public_keys: set[str] | None = None,
        trusted_log_key_ids: set[str] | None = None,
        required_witnesses: int = 0,
        trusted_witness_keys: set[str] | None = None,
    ) -> bool:
        """Confirm one checkpoint is an append-only superset of an earlier one.

        Rejects any rewrite of an earlier record: a changed historical leaf
        changes the old root, so the proof can no longer reconstruct both
        committed roots.
        """
        if trusted_log_public_keys or trusted_log_key_ids or required_witnesses > 0:
            old_issues = checkpoint_trust_issues(
                old_checkpoint,
                trusted_public_keys=trusted_log_public_keys,
                trusted_key_ids=trusted_log_key_ids,
                required_witnesses=required_witnesses,
                trusted_witness_keys=trusted_witness_keys,
            )
            new_issues = checkpoint_trust_issues(
                new_checkpoint,
                trusted_public_keys=trusted_log_public_keys,
                trusted_key_ids=trusted_log_key_ids,
                required_witnesses=required_witnesses,
                trusted_witness_keys=trusted_witness_keys,
            )
            if old_issues or new_issues:
                return False
        old_size = old_checkpoint.get("count")
        new_size = new_checkpoint.get("count")
        if old_size is None or new_size is None:
            return False
        if proof.get("old_size") != old_size or proof.get("new_size") != new_size:
            return False
        old_root = old_checkpoint.get("merkle_root")
        new_root = new_checkpoint.get("merkle_root")
        if old_size == 0:
            return not proof.get("path")
        from agentauth.receipts import c2sp

        roots = c2sp.rfc6962_consistency_roots(
            int(old_size),
            int(new_size),
            [bytes.fromhex(p) for p in proof["path"]],
            bytes.fromhex(old_root),
        )
        if roots is None:
            return False
        return roots[0].hex() == old_root and roots[1].hex() == new_root

    def __len__(self) -> int:
        with self._lock:
            (n,) = self._conn.execute("SELECT COUNT(*) FROM audit_records").fetchone()
            return int(n)


def audit_record_to_dict(record: AuditRecord) -> dict[str, Any]:
    return {
        "seq": record.seq,
        "proof_id": str(record.proof_id),
        "execution_proof_hash": record.execution_proof_hash,
        "action": record.action,
        "authorization_context": record.authorization_context,
        "created_at": record.created_at.isoformat(),
        "prev_hash": record.prev_hash,
        "record_hash": record.record_hash,
        "signature": record.signature,
    }
