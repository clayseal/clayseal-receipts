"""Session-proof aggregation CLI wrappers (SOTA-7)."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from agentauth.receipts.prover import locate_cli


def prove_session(
    *,
    session_id: str,
    actions: list[dict[str, Any]],
    mode: str = "halo2_batch_v1",
) -> bytes | None:
    """Aggregate N policy actions into one session proof via Rust CLI."""
    status = locate_cli()
    if not status.available or not status.binary:
        return None

    with tempfile.TemporaryDirectory() as tmp:
        actions_path = Path(tmp) / "actions.json"
        out = Path(tmp) / "session.json"
        actions_path.write_text(json.dumps(actions, sort_keys=True), encoding="utf-8")
        subprocess.run(
            [
                status.binary,
                "prove-session",
                "--session-id",
                session_id,
                "--actions",
                str(actions_path),
                "--mode",
                mode,
                "--out",
                str(out),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return out.read_bytes()


def verify_session(envelope_json: bytes) -> dict[str, Any]:
    status = locate_cli()
    if not status.available or not status.binary:
        return {"valid": False, "reasons": [status.message]}

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "session.json"
        path.write_bytes(envelope_json)
        proc = subprocess.run(
            [status.binary, "verify-session", "--envelope", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        valid = "valid=true" in proc.stdout
        mode = "unknown"
        for line in proc.stdout.splitlines():
            if line.startswith("valid=") and "mode=" in line:
                mode = line.split("mode=", 1)[1].strip()
        return {"valid": valid, "mode": mode, "reasons": [] if valid else [proc.stdout.strip()]}


def parse_session(blob: bytes) -> dict[str, Any]:
    return json.loads(blob)


def session_proof_bundle_section(envelope: dict[str, Any]) -> dict[str, Any]:
    """Canonical receipt-bundle section for an aggregated session proof envelope."""
    return {
        "envelope": envelope,
        "mode": envelope.get("aggregation_mode"),
        "digest": envelope.get("session_digest"),
    }


def normalize_session_envelope(session_proof: dict[str, Any]) -> dict[str, Any] | None:
    """Return the embedded session envelope dict, if present."""
    if not isinstance(session_proof, dict):
        return None
    envelope = session_proof.get("envelope")
    if isinstance(envelope, dict) and envelope.get("session_digest") and envelope.get("proof_hex"):
        return envelope
    if session_proof.get("session_digest") and session_proof.get("proof_hex"):
        return session_proof
    return None


def verify_bundle_session_proof(
    bundle: dict[str, Any],
    *,
    session_id: str | None,
    policy_commitment: str,
    output_hash: str,
) -> list[str]:
    """Validate optional session_proof section and bind it to the execution proof."""
    section = bundle.get("session_proof")
    if not section:
        return []

    envelope = normalize_session_envelope(section)
    if envelope is None:
        return ["session_proof requires a session envelope with session_digest and proof_hex"]

    issues: list[str] = []
    if session_id and envelope.get("session_id") != session_id:
        issues.append("session_proof session_id does not match execution proof")
    if envelope.get("policy_commitment") != policy_commitment:
        issues.append("session_proof policy_commitment does not match execution proof")

    digest = section.get("digest")
    if digest is not None and digest != envelope.get("session_digest"):
        issues.append("session_proof digest does not match envelope session_digest")

    mode = section.get("mode")
    if mode is not None and mode != envelope.get("aggregation_mode"):
        issues.append("session_proof mode does not match envelope aggregation_mode")

    actions = envelope.get("actions")
    if not isinstance(actions, list) or not actions:
        issues.append("session_proof envelope actions are required")
    else:
        matched = any(
            isinstance(action, dict)
            and action.get("output_hash") == output_hash
            and action.get("policy_commitment") == policy_commitment
            for action in actions
        )
        if not matched:
            issues.append(
                "session_proof envelope does not include an action matching this receipt output_hash and policy_commitment"
            )

    if issues:
        return issues

    check = verify_session(json.dumps(envelope, sort_keys=True).encode("utf-8"))
    if not check.get("valid"):
        for reason in check.get("reasons") or ["session proof cryptographic verification failed"]:
            issues.append(reason)
    return issues
