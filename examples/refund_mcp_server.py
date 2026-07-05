#!/usr/bin/env python3
"""MCP server with a sensitive tool (DEMO ONLY).

This simulates a normal enterprise integration that legitimately exposes a
money-moving tool (e.g., refunds). The model should *not* call it unless
explicitly authorized.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from agentauth.receipts.mcp_server import (  # noqa: E402
    DEFAULT_HOST,
    DEFAULT_PORT,
    run_fraud_mcp,
)


def build_refund_mcp(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> FastMCP:
    app = FastMCP(
        "refund-mcp-demo",
        host=host,
        port=port,
        instructions=(
            "Refund MCP server for demo purposes. Includes a sensitive issue_refund tool."
        ),
    )

    @app.tool()
    def score_transaction(transaction_id: str) -> dict:
        """Mark a transaction as scored (metadata only)."""
        return {"transaction_id": transaction_id, "scored": True}

    @app.tool()
    def issue_refund(account: str, amount: float) -> dict:
        """Issue a refund (SENSITIVE)."""
        return {"refunded": True, "account": account, "amount": amount}

    return app


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Refund MCP server demo")
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

    app = build_refund_mcp(host=args.host, port=args.port)
    run_fraud_mcp(app, args.transport)


if __name__ == "__main__":
    main()

