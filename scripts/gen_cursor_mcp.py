#!/usr/bin/env python3
"""Write .cursor/mcp.json with absolute paths for this repo."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main() -> None:
    root = repo_root()
    server = root / "examples" / "mcp_live_server.py"
    if not server.is_file():
        print(f"Missing server script: {server}", file=sys.stderr)
        sys.exit(1)

    transport = "stdio"
    if len(sys.argv) > 1:
        transport = sys.argv[1]

    config = {
        "mcpServers": {
            "agent-receipts-fraud": {
                "command": sys.executable,
                "args": [str(server)],
                "env": {
                    "AGENT_RECEIPTS_MCP_TRANSPORT": transport,
                },
            }
        }
    }

    out_dir = root / ".cursor"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "mcp.json"
    out_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print("Wrote", out_path)
    print(json.dumps(config, indent=2))


if __name__ == "__main__":
    main()
