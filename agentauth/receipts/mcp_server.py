"""MCP server exposing fraud tools (stdio, SSE, or streamable HTTP).

Reference pilot server only — not for production. HTTP/SSE transports require an
API key when ``AGENT_RECEIPTS_MCP_API_KEY`` is set, and refuse non-localhost binds
without one.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Literal

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette

from agentauth.receipts import fraud_tools
from agentauth.receipts.verifier_auth import ApiKeyMiddleware

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
MCP_API_KEY_ENV = "AGENT_RECEIPTS_MCP_API_KEY"
McpHttpTransport = Literal["sse", "streamable-http"]


def mcp_api_key() -> str | None:
    key = os.environ.get(MCP_API_KEY_ENV, "").strip()
    return key or None


def _is_local_bind(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    return normalized in {"127.0.0.1", "localhost", "::1"}


def validate_http_bind(host: str) -> None:
    """Refuse network-visible binds without an operator API key."""
    if _is_local_bind(host) or mcp_api_key():
        return
    print(
        f"error: refusing to bind MCP server to {host!r} without {MCP_API_KEY_ENV}. "
        "The reference fraud MCP server is for local pilots; set an API key before "
        "exposing it on the network.",
        file=sys.stderr,
    )
    raise SystemExit(2)


def wrap_http_app(starlette_app: Starlette) -> Starlette:
    """Attach API-key middleware when ``AGENT_RECEIPTS_MCP_API_KEY`` is configured."""
    if mcp_api_key():
        starlette_app.add_middleware(ApiKeyMiddleware, env_var=MCP_API_KEY_ENV)
    return starlette_app


def http_starlette_app(app: FastMCP, transport: McpHttpTransport) -> Starlette:
    if transport == "sse":
        starlette_app = app.sse_app()
    else:
        starlette_app = app.streamable_http_app()
    return wrap_http_app(starlette_app)


async def run_http_async(app: FastMCP, transport: McpHttpTransport) -> None:
    import uvicorn

    starlette_app = http_starlette_app(app, transport)
    config = uvicorn.Config(
        starlette_app,
        host=app.settings.host,
        port=app.settings.port,
        log_level=app.settings.log_level.lower(),
    )
    server = uvicorn.Server(config)
    await server.serve()


def run_fraud_mcp(app: FastMCP, transport: str) -> None:
    if transport == "stdio":
        app.run(transport="stdio")
        return
    if transport not in ("sse", "streamable-http"):
        raise ValueError(f"unknown transport: {transport}")
    validate_http_bind(app.settings.host)
    import anyio

    anyio.run(lambda: run_http_async(app, transport))  # type: ignore[arg-type]


def build_fraud_mcp(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> FastMCP:
    app = FastMCP(
        "agent-receipts-fraud",
        host=host,
        port=port,
        instructions=(
            "Fraud-scoring MCP server for Agent Receipts pilots. "
            "Tools return JSON suitable for policy verification."
        ),
    )

    @app.tool()
    def score_fraud_model(transaction_id: str, amount: float) -> dict:
        """Score fraud risk for a transaction; returns decision and fraud_score in [0,1]."""
        return fraud_tools.score_fraud_model(
            {"transaction_id": transaction_id, "amount": amount}
        )

    @app.tool()
    def score_transaction(transaction_id: str) -> dict:
        """Mark a transaction as scored (metadata only)."""
        return fraud_tools.score_transaction({"transaction_id": transaction_id})

    @app.tool()
    def fetch_customer_profile(customer_id: str) -> dict:
        """Fetch a synthetic customer profile tier."""
        return fraud_tools.fetch_customer_profile({"customer_id": customer_id})

    return app


# Default app for `agent-receipts-mcp-server` and tests
mcp = build_fraud_mcp()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Agent Receipts fraud MCP server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default=os.environ.get("AGENT_RECEIPTS_MCP_TRANSPORT", "stdio"),
    )
    parser.add_argument("--host", default=os.environ.get("AGENT_RECEIPTS_MCP_HOST", DEFAULT_HOST))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("AGENT_RECEIPTS_MCP_PORT", str(DEFAULT_PORT))),
    )
    args = parser.parse_args(argv)

    app = build_fraud_mcp(host=args.host, port=args.port)
    run_fraud_mcp(app, args.transport)


if __name__ == "__main__":
    main()
