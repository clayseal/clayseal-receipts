"""Minimal HTTP verifier for receipt bundles (design partner / compliance)."""

from __future__ import annotations

import json
from typing import Any

from agentauth.receipts._version import __version__
from agentauth.receipts.diagnostics import run_diagnostics
from agentauth.receipts.export import verify_receipt_bundle
from agentauth.receipts.receipt_schema import SUPPORTED_RECEIPT_BUNDLE_SCHEMAS
from agentauth.receipts.verification import VerifyErrorCode
from agentauth.receipts.verifier_auth import (
    ApiKeyMiddleware,
    RateLimitMiddleware,
    max_body_bytes,
    rate_limit_per_minute,
    require_prover_for_ready,
)

try:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route
except ImportError as exc:  # pragma: no cover
    Starlette = None  # type: ignore[misc, assignment]
    _STARLETTE_IMPORT_ERROR = exc
else:
    _STARLETTE_IMPORT_ERROR = None


def require_verifier_deps() -> None:
    if _STARLETTE_IMPORT_ERROR is not None:
        raise ImportError(
            "HTTP verifier requires starlette. Install with: pip install 'agent-receipts[verifier]'"
        ) from _STARLETTE_IMPORT_ERROR


def verify_bundle_payload(
    bundle: dict[str, Any],
    *,
    min_assurance_tier: str | None = None,
) -> dict[str, Any]:
    """Run verification and return API-shaped response."""
    try:
        result = verify_receipt_bundle(bundle, min_assurance_tier=min_assurance_tier)
    except (KeyError, TypeError, ValueError) as exc:
        message = f"malformed receipt bundle: {exc}"
        return {
            "valid": False,
            "reasons": [message],
            "issues": [
                {
                    "code": VerifyErrorCode.SCHEMA_MISMATCH.value,
                    "message": message,
                }
            ],
            "cryptographic": None,
            "decision": None,
            "authority": bundle.get("authority"),
            "session": bundle.get("session"),
            "assurance": None,
            "signatures": None,
            "schema": bundle.get("schema"),
            "proof_id": None,
            "sdk_version": bundle.get("sdk_version"),
            "verifier_version": __version__,
        }
    return {
        "valid": result["valid"],
        "reasons": result.get("reasons", []),
        "issues": result.get("issues", []),
        "cryptographic": result.get("cryptographic"),
        "decision": result.get("decision"),
        "authority": bundle.get("authority"),
        "session": bundle.get("session"),
        "assurance": result.get("assurance"),
        "signatures": result.get("signatures"),
        "schema": bundle.get("schema"),
        "proof_id": bundle.get("execution_proof", {}).get("proof_id"),
        "sdk_version": bundle.get("sdk_version"),
        "verifier_version": __version__,
    }


async def health(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "verifier_version": __version__,
        }
    )


async def ready(_: Request) -> JSONResponse:
    diag = run_diagnostics(require_prover=require_prover_for_ready())
    ok = diag["ready"]
    status = 200 if ok else 503
    return JSONResponse(
        {
            "ready": ok,
            "prove_ready": diag.get("prove_ready", False),
            "required_failures": diag.get("required_failures", []),
            "verifier_version": __version__,
        },
        status_code=status,
    )


async def version(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "verifier_version": __version__,
            "supported_schemas": list(SUPPORTED_RECEIPT_BUNDLE_SCHEMAS),
        }
    )


async def verify_v1(request: Request) -> JSONResponse:
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
    if invalid_tier:
        return JSONResponse(payload, status_code=400)
    return JSONResponse(payload)


def create_app() -> Starlette:
    require_verifier_deps()
    app = Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/ready", ready, methods=["GET"]),
            Route("/v1/version", version, methods=["GET"]),
            Route("/v1/verify", verify_v1, methods=["POST"]),
        ],
    )
    app.add_middleware(RateLimitMiddleware, limit_per_minute=rate_limit_per_minute())
    app.add_middleware(ApiKeyMiddleware)
    return app


_app: Any = None


def get_app() -> Starlette:
    global _app
    if _app is None:
        _app = create_app()
    return _app
