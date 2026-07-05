"""Structured logging setup for partner deployments."""

from __future__ import annotations

import logging
import os
import sys


def setup_logging(name: str = "agent_receipts") -> logging.Logger:
    level_name = os.environ.get("AGENT_RECEIPTS_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger(name)
    if root.handlers:
        return root

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )
    root.addHandler(handler)
    root.setLevel(level)
    return root
