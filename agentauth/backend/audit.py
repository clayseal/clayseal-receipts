"""Append-only identity event log (hash-chained, DB-backed).

``record_event`` is the single choke point the Identity Service calls to record
a credential lifecycle event (issuance, revocation, key rotation, attestor /
registration changes). Each event is appended to the ``audit_events`` table as a
tamper-evident hash chain: ``entry_hash = H(sequence, prev_hash, ts, type,
customer_id, ...fields)`` and each row links to the previous via ``prev_hash``.

This replaces the legacy flat ``audit.jsonl`` file: the trail now lives in the
same durable, queryable SQLite store as the rest of the identity data, so it can
be filtered by tenant and verified without parsing a side file.

Call sites pass no DB session: ``record_event`` opens its own short-lived
session so the audit write is independent of the caller's transaction (an
append-only log should persist regardless of the surrounding request).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError

from .db import SessionLocal
from .models import AuditEvent

_lock = threading.Lock()
_CHAIN_SCHEMA = "agentauth.audit.v1"
_APPEND_RETRIES = 5


def _canonical_json(value: object) -> str:
    return json.dumps(value, default=str, sort_keys=True, separators=(",", ":"))


def _record_hash(record: dict) -> str:
    """Hash the canonical event material (everything but the hash itself)."""
    material = {key: value for key, value in record.items() if key != "entry_hash"}
    return hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()


def _record_from_row(row: AuditEvent) -> dict:
    """Reconstruct the hashed event material from a stored row."""
    return {
        "schema": _CHAIN_SCHEMA,
        "sequence": row.sequence,
        "prev_hash": row.prev_hash,
        "ts": row.ts,
        "type": row.type,
        "customer_id": row.customer_id,
        **(row.payload or {}),
    }


def record_event(event_type: str, customer_id: str, **fields: object) -> dict:
    """Append an identity event to the hash-chained log and return the record."""
    for attempt in range(_APPEND_RETRIES):
        with _lock, SessionLocal() as db:
            try:
                last = db.scalars(
                    select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1)
                ).first()
                prev_hash = last.entry_hash if last is not None else None
                next_sequence = (last.sequence + 1) if last is not None else 1

                ts = datetime.utcnow().isoformat() + "Z"
                record = {
                    "schema": _CHAIN_SCHEMA,
                    "sequence": next_sequence,
                    "prev_hash": prev_hash,
                    "ts": ts,
                    "type": event_type,
                    "customer_id": customer_id,
                    **fields,
                }
                record["entry_hash"] = _record_hash(record)

                db.add(
                    AuditEvent(
                        sequence=next_sequence,
                        customer_id=customer_id,
                        type=event_type,
                        ts=ts,
                        payload=dict(fields),
                        prev_hash=prev_hash,
                        entry_hash=record["entry_hash"],
                    )
                )
                db.commit()
                return record
            except (IntegrityError, OperationalError):
                db.rollback()
                if attempt == _APPEND_RETRIES - 1:
                    raise
        time.sleep(0.01 * (attempt + 1))
    raise RuntimeError("failed to append audit event")


def read_events(customer_id: str | None = None) -> list[dict]:
    """Return audit events (oldest first), optionally filtered by tenant.

    Each event includes its ``entry_hash``; this is the queryable replacement
    for reading the old JSONL file line by line.
    """
    stmt = select(AuditEvent).order_by(AuditEvent.sequence)
    if customer_id is not None:
        stmt = stmt.where(AuditEvent.customer_id == customer_id)
    with SessionLocal() as db:
        rows = db.scalars(stmt).all()
    return [{**_record_from_row(row), "entry_hash": row.entry_hash} for row in rows]


def verify_event_log() -> list[str]:
    """Return integrity issues for the identity event log (empty == intact)."""
    with SessionLocal() as db:
        rows = db.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()

    issues: list[str] = []
    expected_prev_hash: str | None = None
    expected_sequence = 1
    for row in rows:
        if row.sequence != expected_sequence:
            issues.append(
                f"sequence {row.sequence}: expected {expected_sequence}"
            )
        if row.prev_hash != expected_prev_hash:
            issues.append(f"sequence {row.sequence}: prev_hash mismatch")
        if _record_hash(_record_from_row(row)) != row.entry_hash:
            issues.append(f"sequence {row.sequence}: entry_hash mismatch")
        expected_prev_hash = row.entry_hash
        expected_sequence += 1

    return issues
