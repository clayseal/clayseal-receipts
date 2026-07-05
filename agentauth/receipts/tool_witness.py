"""Optional tool-receiver co-signatures (SOTA-16c).

MCP / tool endpoints can emit a separate signature over action input/output hashes
and a mandate reference. This is a witness-layer add-on — it does not replace the
operator ZK compliance bundle.
"""

from __future__ import annotations

from typing import Any

from agentauth.core.signing import SigningKey, verify

TOOL_WITNESS_SCHEMA = "agent-receipts.tool-witness.v1"


def build_tool_witness_body(
    *,
    input_hash: str,
    output_hash: str,
    mandate_ref: str,
    action_name: str,
) -> dict[str, Any]:
    return {
        "schema": TOOL_WITNESS_SCHEMA,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "mandate_ref": mandate_ref,
        "action_name": action_name,
    }


def sign_tool_witness(
    body: dict[str, Any],
    tool_key: SigningKey,
) -> dict[str, Any]:
    """Return a bundle ``signatures[]`` entry with ``role: tool``."""
    signature = tool_key.sign(body)
    return {"role": "tool", "witness_body": body, **signature}


def verify_tool_witness(descriptor: dict[str, Any]) -> list[str]:
    """Verify a tool witness descriptor independently of envelope signatures."""
    if descriptor.get("role") != "tool":
        return ["descriptor is not a tool witness"]
    body = descriptor.get("witness_body")
    if not isinstance(body, dict):
        return ["tool witness missing witness_body"]
    if body.get("schema") != TOOL_WITNESS_SCHEMA:
        return [f"unsupported tool witness schema: {body.get('schema')!r}"]
    sig = {k: v for k, v in descriptor.items() if k not in ("role", "witness_body")}
    if not verify(body, sig):
        return ["tool witness signature invalid"]
    return []


def tool_witnesses_from_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    signatures = bundle.get("signatures", [])
    if not isinstance(signatures, list):
        return []
    return [item for item in signatures if isinstance(item, dict) and item.get("role") == "tool"]
