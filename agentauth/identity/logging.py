"""Structured logging for the SDK.

Provides a configured ``agentauth`` logger. Format is auto-detected from the
environment (JSON when running under a structured-logging setup, plain text
otherwise) and can be overridden per client.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Optional

_LOGGER_NAME = "agentauth"


def _detect_format() -> str:
    """Pick a default log format from the environment.

    Honour an explicit ``AGENTAUTH_LOG_FORMAT`` first; otherwise emit JSON when
    the process looks like a structured/observability environment (Datadog,
    OpenTelemetry, JSON log indicator, or non-TTY stdout), else plain text.
    """
    explicit = os.getenv("AGENTAUTH_LOG_FORMAT")
    if explicit:
        return explicit.lower()
    structured_signals = ("DD_SERVICE", "OTEL_SERVICE_NAME", "JSON_LOGS")
    if any(os.getenv(k) for k in structured_signals):
        return "json"
    if not sys.stdout.isatty():
        return "json"
    return "text"


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "agentauth", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload, default=str)


def get_logger(
    *,
    log_format: Optional[str] = None,
    level: int = logging.INFO,
) -> logging.Logger:
    """Return a configured ``agentauth`` logger.

    Idempotent: re-configures the handler/formatter when called again (e.g. a
    second client with a different ``log_format``) without stacking handlers.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    fmt = (log_format or _detect_format()).lower()
    handler: logging.Handler
    if logger.handlers:
        handler = logger.handlers[0]
    else:
        handler = logging.StreamHandler(sys.stdout)
        logger.addHandler(handler)

    if fmt == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [agentauth] %(message)s")
        )
    return logger
