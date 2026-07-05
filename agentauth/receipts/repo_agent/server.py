#!/usr/bin/env python3
"""HTTP API for the agent-run comparison UI."""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from agentauth.receipts.repo_agent.engine import get_session

app = FastAPI(title="Agent run comparison", version="1.0.0")

_origins = os.getenv(
    "REPO_AGENT_UI_CORS",
    "http://localhost:5173,http://127.0.0.1:5173",
).split(",")

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
    uvicorn.run(
        "agentauth.receipts.repo_agent.server:app",
        host=host,
        port=port,
        reload=False,
    )


if __name__ == "__main__":
    main()
