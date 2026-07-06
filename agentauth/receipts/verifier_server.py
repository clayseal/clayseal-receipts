"""Minimal HTTP verifier for receipt bundles (design partner / compliance).

Also serves the SCRAPI face of a SCITT Transparency Service (``POST /entries``,
``GET /entries/{entry_id}``, ``GET /.well-known/scitt-keys``) so SCITT-aware
clients can register Signed Statements here and obtain RFC 9942 COSE Receipts.
The transparency log is in-process (one Merkle tree per server process); pin
``AGENTAUTH_SCITT_SIGNING_KEY_HEX`` so receipts stay verifiable across restarts.
"""

from __future__ import annotations

import json
import os
from typing import Any

from agentauth.receipts import scitt, scrapi
from agentauth.receipts._version import __version__
from agentauth.receipts.diagnostics import run_diagnostics
from agentauth.receipts.environment import enforce_production_soundness, is_production
from agentauth.receipts.export import verify_receipt_bundle
from agentauth.receipts.receipt_schema import SUPPORTED_RECEIPT_BUNDLE_SCHEMAS
from agentauth.receipts.verification import VerifyErrorCode
from agentauth.receipts.verifier_auth import (
    ApiKeyMiddleware,
    RateLimitMiddleware,
    max_body_bytes,
    rate_limit_per_minute,
    require_identity_binding_from_env,
    require_prover_for_ready,
)

TRANSPARENCY_SINGLE_WRITER_ENV = "AGENT_RECEIPTS_TRANSPARENCY_SINGLE_WRITER"

try:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
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
    require_identity_binding: bool | None = None,
) -> dict[str, Any]:
    """Run verification and return API-shaped response."""
    if require_identity_binding is None:
        require_identity_binding = require_identity_binding_from_env()
    try:
        result = verify_receipt_bundle(
            bundle,
            min_assurance_tier=min_assurance_tier,
            require_identity_binding=require_identity_binding,
        )
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


# --------------------------------------------------------------------------- #
# SCRAPI: this server as a SCITT Transparency Service
# --------------------------------------------------------------------------- #
_transparency_service: scitt.TransparencyService | None = None
_entry_index: dict[str, int] = {}


def get_transparency_service() -> scitt.TransparencyService:
    global _transparency_service
    if _transparency_service is None:
        _transparency_service = scitt.TransparencyService(
            scrapi.load_service_signing_key(), service_id=scrapi.service_id_from_env()
        )
    return _transparency_service


def _reset_transparency_service() -> None:
    """Test hook: drop the in-process log so each test starts from an empty tree."""
    global _transparency_service
    _transparency_service = None
    _entry_index.clear()


def _problem_response(status: int, title: str, detail: str) -> Response:
    return Response(
        scrapi.problem_details(title, detail),
        status_code=status,
        media_type=scrapi.MEDIA_PROBLEM,
    )


def _transparency_writer_allowed() -> bool:
    """The SCITT log is an in-process Merkle tree (one per process), so its writes
    cannot be load-balanced across replicas without forking the tree. In production
    the write path is refused unless exactly one instance is flagged as the single
    writer via ``AGENT_RECEIPTS_TRANSPARENCY_SINGLE_WRITER=1``."""
    if not is_production():
        return True
    return os.environ.get(TRANSPARENCY_SINGLE_WRITER_ENV, "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


async def scrapi_register(request: Request) -> Response:
    if not _transparency_writer_allowed():
        return _problem_response(
            409,
            "Transparency Registration Disabled",
            "the SCITT transparency log is an in-process single-writer tree; set "
            f"{TRANSPARENCY_SINGLE_WRITER_ENV}=1 on exactly one instance, or back it with a "
            "shared durable log. Stateless /v1/verify remains available on every replica.",
        )
    body = await request.body()
    if len(body) > max_body_bytes():
        return _problem_response(413, "Payload Too Large", "Signed Statement exceeds size limit")
    content_type = request.headers.get("content-type", "").split(";")[0].strip()
    if content_type != scrapi.MEDIA_COSE:
        return _problem_response(
            400, "Unsupported Content Type", f"expected {scrapi.MEDIA_COSE}"
        )
    try:
        scrapi.check_registration_policy(body)
    except scrapi.RegistrationRejected as exc:
        return _problem_response(400, exc.title, exc.detail)

    service = get_transparency_service()
    entry_id = scrapi.entry_id_for_statement(body)
    index = _entry_index.get(entry_id)
    if index is None:
        # Registration is synchronous (the tree is in-process), so the 201
        # flow always applies; 202 never occurs here.
        index = service.tree_size
        receipt = service.register(body)
        _entry_index[entry_id] = index
    else:
        receipt = service.receipt_for(index)  # idempotent re-registration
    return Response(
        receipt,
        status_code=201,
        media_type=scrapi.MEDIA_COSE,
        headers={"Location": f"/entries/{entry_id}"},
    )


async def scrapi_resolve(request: Request) -> Response:
    entry_id = request.path_params["entry_id"]
    index = _entry_index.get(entry_id)
    if index is None:
        return _problem_response(404, "Not Found", f"no receipt for entry {entry_id}")
    receipt = get_transparency_service().receipt_for(index)
    return Response(
        receipt,
        media_type=scrapi.MEDIA_COSE,
        headers={"Location": f"/entries/{entry_id}"},
    )


async def scitt_keys(_: Request) -> Response:
    service = get_transparency_service()
    return Response(
        scrapi.cose_key_set([service.signing_key]),
        media_type=scrapi.MEDIA_CBOR,
    )


def create_app() -> Starlette:
    require_verifier_deps()
    # Fail closed if a production verifier has a soundness escape hatch set.
    enforce_production_soundness()
    # POST /v1/verify is stateless: its verdict is a pure function of the request
    # body plus process env (trust anchors, tier/identity requirements). It holds no
    # cross-request state, so it scales horizontally behind a load balancer with no
    # shared store. The only stateful surface is the in-process SCITT /entries log
    # (guarded above for single-writer). Rate limiting here is per-instance and
    # advisory; the API gateway/WAF is authoritative behind more than one instance.
    app = Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/ready", ready, methods=["GET"]),
            Route("/v1/version", version, methods=["GET"]),
            Route("/v1/verify", verify_v1, methods=["POST"]),
            Route("/entries", scrapi_register, methods=["POST"]),
            Route("/entries/{entry_id}", scrapi_resolve, methods=["GET"]),
            Route(scrapi.SCITT_KEYS_PATH, scitt_keys, methods=["GET"]),
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
