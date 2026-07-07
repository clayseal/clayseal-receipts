"""Verifier security: API key auth and simple rate limiting."""

from __future__ import annotations

import hmac
import os
import sys
import time
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

VERIFIER_API_KEY_ENV = "AGENT_RECEIPTS_VERIFIER_API_KEY"
VERIFIER_REQUIRE_API_KEY_ENV = "AGENT_RECEIPTS_VERIFIER_REQUIRE_API_KEY"


def verifier_api_key() -> str | None:
    key = os.environ.get(VERIFIER_API_KEY_ENV, "").strip()
    return key or None


def verifier_require_api_key() -> bool:
    return os.environ.get(VERIFIER_REQUIRE_API_KEY_ENV, "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def _is_local_bind(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    return normalized in {"127.0.0.1", "localhost", "::1"}


def validate_verifier_bind(host: str) -> None:
    """Refuse network-visible binds without an operator API key."""
    if _is_local_bind(host) or verifier_api_key():
        return
    print(
        f"error: refusing to bind verifier to {host!r} without {VERIFIER_API_KEY_ENV}. "
        "Set an API key before exposing the HTTP verifier on the network.",
        file=sys.stderr,
    )
    raise SystemExit(2)


def _extract_api_key(request: Request) -> str | None:
    header = request.headers.get("x-api-key")
    if header:
        return header.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


class ApiKeyMiddleware(BaseHTTPMiddleware):
    """Require API key on protected routes when configured or explicitly required."""

    # Well-known documents are public by design: RFC 9728 protected-resource
    # metadata is how clients discover the authorization server BEFORE they
    # have credentials, and SCITT keys are public key material.
    PUBLIC_PATHS = frozenset(
        {
            "/health",
            "/ready",
            "/v1/version",
            "/.well-known/oauth-protected-resource",
            "/.well-known/scitt-keys",
        }
    )

    def __init__(
        self,
        app: Any,
        *,
        env_var: str = VERIFIER_API_KEY_ENV,
        protected_paths: Iterable[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.env_var = env_var
        self.protected_paths = frozenset(protected_paths or ()) or None

    def _auth_required(self) -> bool:
        if os.environ.get(self.env_var, "").strip():
            return True
        return self.env_var == VERIFIER_API_KEY_ENV and verifier_require_api_key()

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if self.protected_paths is not None and request.url.path not in self.protected_paths:
            return await call_next(request)
        if not self._auth_required() or request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)

        required = os.environ.get(self.env_var, "").strip() or None
        if required is None:
            return JSONResponse(
                {
                    "error": "misconfigured",
                    "detail": f"{self.env_var} must be set when API key auth is required",
                },
                status_code=503,
            )

        provided = _extract_api_key(request)
        if provided is None or not hmac.compare_digest(provided, required):
            return JSONResponse(
                {"error": "unauthorized", "detail": "missing or invalid API key"},
                status_code=401,
            )
        return await call_next(request)


def _rate_limit_identity(request: Request) -> str:
    """Bucket by API key when present, otherwise by client IP."""
    api_key = _extract_api_key(request)
    if api_key:
        return f"key:{api_key}"
    client = request.client.host if request.client else "unknown"
    return f"ip:{client}"


# Stateful/expensive POST surfaces that must be throttled (the transparency
# service /entries write path was previously unthrottled).
RATE_LIMITED_PATHS = frozenset({"/v1/verify", "/entries"})


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory rate limit keyed by API key or IP (pilot only; use gateway in production)."""

    def __init__(self, app: Any, *, limit_per_minute: int) -> None:
        super().__init__(app)
        self.limit = limit_per_minute
        self._hits: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if self.limit <= 0 or request.url.path not in RATE_LIMITED_PATHS:
            return await call_next(request)

        identity = _rate_limit_identity(request)
        now = time.monotonic()
        window = self._hits[identity]
        window[:] = [t for t in window if now - t < 60.0]
        if len(window) >= self.limit:
            return JSONResponse(
                {"error": "rate_limit_exceeded", "detail": f"max {self.limit} requests/minute"},
                status_code=429,
            )
        window.append(now)
        return await call_next(request)


def rate_limit_per_minute() -> int:
    raw = os.environ.get("AGENT_RECEIPTS_VERIFIER_RATE_LIMIT", "120")
    try:
        return int(raw)
    except ValueError:
        return 120


def max_body_bytes() -> int:
    raw = os.environ.get("AGENT_RECEIPTS_MAX_BODY_BYTES", str(1024 * 1024))
    try:
        return int(raw)
    except ValueError:
        return 1024 * 1024


def require_prover_for_ready() -> bool:
    from agentauth.receipts.environment import require_prover_active

    # Explicit AGENT_RECEIPTS_REQUIRE_PROVER, or implied by AGENT_RECEIPTS_ENV=production.
    return require_prover_active()


def require_identity_binding_from_env() -> bool:
    """Verifier-side toggle: reject authority-unbound bundles on /v1/verify."""
    explicit = os.environ.get("AGENT_RECEIPTS_REQUIRE_IDENTITY_BINDING", "").strip().lower()
    if explicit in ("0", "false", "no", "off"):
        return False
    if explicit in ("1", "true", "yes", "on"):
        return True
    from agentauth.receipts.environment import is_production

    return is_production()
