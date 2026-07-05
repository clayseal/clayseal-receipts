"""SDK logging format detection and formatter tests."""
from __future__ import annotations

import json
import logging

from agentauth.identity import logging as sdk_logging


def test_detect_format_honors_explicit_env(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_LOG_FORMAT", "TEXT")

    assert sdk_logging._detect_format() == "text"


def test_detect_format_uses_structured_environment(monkeypatch):
    monkeypatch.delenv("AGENTAUTH_LOG_FORMAT", raising=False)
    monkeypatch.setenv("DD_SERVICE", "agentauth-tests")

    assert sdk_logging._detect_format() == "json"


def test_detect_format_uses_text_for_tty_without_structured_signals(monkeypatch):
    monkeypatch.delenv("AGENTAUTH_LOG_FORMAT", raising=False)
    monkeypatch.delenv("DD_SERVICE", raising=False)
    monkeypatch.delenv("OTEL_SERVICE_NAME", raising=False)
    monkeypatch.delenv("JSON_LOGS", raising=False)
    monkeypatch.setattr(sdk_logging.sys.stdout, "isatty", lambda: True)

    assert sdk_logging._detect_format() == "text"


def test_get_logger_formats_json_extra_and_reconfigures_text():
    logger = logging.getLogger("agentauth")
    logger.handlers.clear()

    configured = sdk_logging.get_logger(log_format="json", level=logging.DEBUG)
    handler = configured.handlers[0]
    record = configured.makeRecord(
        "agentauth",
        logging.INFO,
        __file__,
        1,
        "identified",
        (),
        None,
        extra={"agentauth": {"agent_id": "agent-1", "customer_id": "cust-1"}},
    )

    payload = json.loads(handler.format(record))
    assert payload["message"] == "identified"
    assert payload["agent_id"] == "agent-1"
    assert payload["customer_id"] == "cust-1"

    reconfigured = sdk_logging.get_logger(log_format="text")
    assert reconfigured is configured
    assert len(reconfigured.handlers) == 1
    assert "%(asctime)s" in reconfigured.handlers[0].formatter._fmt
