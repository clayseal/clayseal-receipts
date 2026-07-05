"""Structured audit helpers for preview paths."""

from __future__ import annotations


def info(event: str, **fields: object) -> None:
    """Emit a structured audit line (stdout in dev)."""
    parts = " ".join(f"{k}={v!r}" for k, v in sorted(fields.items()))
    print(f"audit {event} {parts}".strip())
