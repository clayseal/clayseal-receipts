"""Receipt verification endpoints, mounted into the hosted service.

The same backend that attests identity (the identity router) also verifies the
execution receipts produced downstream, so one process answers both *who is this
agent* and *what did it actually do*. Verification is a public, cross-tenant
operation — anyone holding a receipt can check it — so these routes carry no
``X-API-Key`` tenant dependency.

Verification logic is shared with the standalone ``arctl serve`` verifier via
``agentauth.receipts.verifier_server.verify_bundle_payload`` so the two never
diverge.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from agentauth.receipts._version import __version__ as receipts_version
from agentauth.receipts.receipt_schema import SUPPORTED_RECEIPT_BUNDLE_SCHEMAS
from agentauth.receipts.verifier_auth import max_body_bytes
from agentauth.receipts.verifier_server import verify_bundle_payload

router = APIRouter(tags=["verifier"])


@router.get("/v1/version")
def verifier_version() -> dict:
    """Supported receipt-bundle schemas and the verifier version."""
    return {
        "verifier_version": receipts_version,
        "supported_schemas": list(SUPPORTED_RECEIPT_BUNDLE_SCHEMAS),
    }


@router.post("/v1/verify")
async def verify(request: Request) -> JSONResponse:
    """Verify a receipt bundle. Returns the structured verification result."""
    limit = max_body_bytes()
    body_bytes = await request.body()
    if len(body_bytes) > limit:
        return JSONResponse(
            {
                "valid": False,
                "reasons": [f"request body exceeds {limit} bytes"],
            },
            status_code=413,
        )
    try:
        body = json.loads(body_bytes)
    except json.JSONDecodeError:
        return JSONResponse(
            {"valid": False, "reasons": ["request body must be JSON"]},
            status_code=400,
        )
    if not isinstance(body, dict):
        return JSONResponse(
            {"valid": False, "reasons": ["request body must be a JSON object"]},
            status_code=400,
        )
    min_tier = request.query_params.get("min_assurance_tier")
    payload = verify_bundle_payload(body, min_assurance_tier=min_tier)
    invalid_tier = any(
        issue.get("code") == "unsupported_assurance"
        and issue.get("message", "").startswith("invalid min_assurance_tier:")
        for issue in payload.get("issues", [])
    )
    return JSONResponse(payload, status_code=400 if invalid_tier else 200)
