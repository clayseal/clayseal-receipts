#!/usr/bin/env python3
"""Entrypoint for stdio MCP server (spawned by mcp_live_client.py)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentauth.receipts.mcp_server import main  # noqa: E402

if __name__ == "__main__":
    main()
