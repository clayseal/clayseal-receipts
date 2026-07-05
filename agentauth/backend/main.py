"""FastAPI application factory + global error handling."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agentauth.receipts.verifier_auth import (
    ApiKeyMiddleware,
    RateLimitMiddleware,
    rate_limit_per_minute,
)

from . import __version__
from .config import get_settings
from .db import init_db
from .errors import AgentAuthError
from .routers import identity, verifier
from .secret_encryption import (
    encryption_enabled,
    secret_encryption_required,
    validate_secret_encryption_config,
)


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentAuth",
        version=__version__,
        description=(
            "Attested identity and verifiable execution receipts for AI agents "
            "-- issues JWT-SVID credentials and verifies receipt bundles."
        ),
    )

    # Allow the browser dashboard (a separate origin) to call the API with the
    # X-API-Key header. Origins are configurable via AGENTAUTH_CORS_ORIGINS.
    origins = get_settings().cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
    )
    app.add_middleware(RateLimitMiddleware, limit_per_minute=rate_limit_per_minute())
    app.add_middleware(ApiKeyMiddleware, protected_paths={"/v1/verify"})
    # ClientCertMiddleware added last = runs first on incoming requests, so
    # request.state.client_cert_der is populated before any auth dependency fires.
    # It is always registered; it self-disables per-request when mtls_enabled=False.
    from .mtls import ClientCertMiddleware
    app.add_middleware(ClientCertMiddleware)

    @app.on_event("startup")
    def _startup() -> None:
        validate_secret_encryption_config(get_settings().database_url)
        init_db()

    @app.exception_handler(AgentAuthError)
    async def _agentauth_error_handler(_request: Request, exc: AgentAuthError) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict())

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        settings = get_settings()
        return {
            "status": "ok",
            "version": __version__,
            "secret_encryption": {
                "enabled": encryption_enabled(),
                "required": secret_encryption_required(settings.database_url),
            },
        }

    app.include_router(identity.router)
    app.include_router(verifier.router)
    return app


app = create_app()
