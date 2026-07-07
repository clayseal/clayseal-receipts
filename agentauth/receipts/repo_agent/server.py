#!/usr/bin/env python3
"""HTTP API for the agent-run comparison UI (demo/local only)."""

from __future__ import annotations

import hmac
import os
import sys
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from agentauth.receipts.repo_agent.engine import get_session

REPO_AGENT_UI_API_KEY_ENV = "REPO_AGENT_UI_API_KEY"
REPO_AGENT_UI_REQUIRE_API_KEY_ENV = "REPO_AGENT_UI_REQUIRE_API_KEY"
_PRODUCTION_ENVS = frozenset({"production", "prod"})


def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _is_local_bind(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    return normalized in {"127.0.0.1", "localhost", "::1"}


def _api_key() -> str | None:
    value = os.getenv(REPO_AGENT_UI_API_KEY_ENV, "").strip()
    return value or None


def validate_repo_agent_bind(host: str) -> None:
    """Refuse network-visible binds without an operator API key."""
    if _is_local_bind(host) or _api_key():
        return
    print(
        f"error: refusing to bind repo-agent UI to {host!r} without "
        f"{REPO_AGENT_UI_API_KEY_ENV}. This server can drive shell execution.",
        file=sys.stderr,
    )
    raise SystemExit(2)


def _deployment_is_production() -> bool:
    return os.getenv("AGENTAUTH_ENV", "").strip().lower() in _PRODUCTION_ENVS or os.getenv(
        "AGENT_RECEIPTS_ENV", ""
    ).strip().lower() in _PRODUCTION_ENVS


class RepoAgentApiKeyMiddleware(BaseHTTPMiddleware):
    PUBLIC_PATHS = frozenset({"/health"})

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        configured = _api_key()
        required = _env_truthy(REPO_AGENT_UI_REQUIRE_API_KEY_ENV) or bool(configured)
        if _deployment_is_production():
            required = True
        if not required:
            return await call_next(request)
        if configured is None:
            return JSONResponse(
                status_code=503,
                content={"detail": f"{REPO_AGENT_UI_API_KEY_ENV} is required in production"},
            )
        provided = request.headers.get("x-api-key") or ""
        auth = request.headers.get("authorization", "")
        if not provided and auth.lower().startswith("bearer "):
            provided = auth[7:].strip()
        if not provided or not hmac.compare_digest(provided, configured):
            return JSONResponse(status_code=401, content={"detail": "unauthorized"})
        return await call_next(request)


app = FastAPI(title="Agent run comparison", version="1.0.0")

_origins = os.getenv(
    "REPO_AGENT_UI_CORS",
    "http://localhost:5173,http://127.0.0.1:5173",
).split(",")

app.add_middleware(RepoAgentApiKeyMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/repo/files")
def repo_files() -> dict[str, Any]:
    session = get_session()
    return {"files": session.repo_files()}


@app.get("/api/repo/file")
def repo_file(path: str = Query(..., min_length=1)) -> dict[str, str]:
    session = get_session()
    try:
        return {"path": path, "content": session.repo_file(path)}
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/run/state")
def agent_state() -> dict[str, Any]:
    return get_session().state()


@app.post("/api/run/reset")
def agent_reset() -> dict[str, Any]:
    session = get_session()
    session.reset()
    return session.state()


@app.post("/api/run/step")
def agent_step() -> dict[str, Any]:
    session = get_session()
    beat = session.advance()
    return {"beat": beat.to_dict(), "state": session.state()}


@app.post("/api/run/verify")
def agent_verify() -> dict[str, Any]:
    return get_session().verify()


def main() -> None:
    import uvicorn

    host = os.getenv("REPO_AGENT_UI_HOST", "127.0.0.1")
    port = int(os.getenv("REPO_AGENT_UI_PORT", "8790"))
    validate_repo_agent_bind(host)
    if _deployment_is_production() and not _api_key():
        raise SystemExit(
            f"{REPO_AGENT_UI_API_KEY_ENV} is required when running the repo-agent UI in production"
        )
    uvicorn.run(
        "agentauth.receipts.repo_agent.server:app",
        host=host,
        port=port,
        reload=False,
    )


if __name__ == "__main__":
    main()
