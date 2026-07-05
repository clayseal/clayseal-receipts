"""Configuration for the AgentAuth MCP gate.

Everything is path/env driven so the same server can gate different repos. The
operator material (mandate, gate signing key, policy) is read here and never
exposed to the agent.
"""

from __future__ import annotations

import os
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    return Path(raw).expanduser().resolve() if raw else default


# --- agent-receipts checkout + Halo2 prover CLI ------------------------------- #
# The receipts SDK is consumed from this sibling checkout. The compiled Rust CLI
# (target/release/agent-receipts) is what produces/verifies the Halo2 policy
# proof; agentauth.receipts.prover.locate_cli() reads AGENT_RECEIPTS_CLI.
AGENT_RECEIPTS_SRC = _env_path(
    "AGENT_RECEIPTS_SRC", (HERE.parent / "agent-receipts").resolve()
)
DEFAULT_CLI = AGENT_RECEIPTS_SRC / "target" / "release" / "agent-receipts"
AGENT_RECEIPTS_CLI = _env_path("AGENT_RECEIPTS_CLI", DEFAULT_CLI)

# Make the CLI discoverable to the SDK for this process (prover.locate_cli()).
if AGENT_RECEIPTS_CLI.exists():
    os.environ.setdefault("AGENT_RECEIPTS_CLI", str(AGENT_RECEIPTS_CLI))


# --- operator material -------------------------------------------------------- #
MANDATE_PATH = _env_path("AGENTAUTH_MCP_MANDATE", HERE / "mandates" / "swe-triage.authorization.json")
POLICY_PATH = _env_path("AGENTAUTH_MCP_POLICY", HERE / "policies" / "pr_gate.policy.yaml")
GATE_KEY_PATH = _env_path("AGENTAUTH_MCP_GATE_KEY", HERE / "keys" / "gate_ed25519.key")

# Where finalized receipt bundles are written for the operator/CI. Per-session
# audit chains live under AUDIT_DIR/<token>.sqlite.
RECEIPTS_DIR = _env_path("AGENTAUTH_MCP_RECEIPTS_DIR", HERE / ".receipts")
AUDIT_DIR = _env_path("AGENTAUTH_MCP_AUDIT_DIR", HERE / ".audit")

# The path (relative to the gated repo root) where the agent must commit the
# finalized bundle so CI can find it. Surfaced to the agent in finalize output.
RECEIPT_COMMIT_PATH_TEMPLATE = ".agentauth/receipts/{session}.json"


# --- identity / tenant -------------------------------------------------------- #
TENANT_ORG = os.environ.get("AGENTAUTH_MCP_ORG", "acme-payments")
AGENT_TYPE = os.environ.get("AGENTAUTH_MCP_AGENT_TYPE", "autonomous-coding-agent")
SESSION_TTL_SECONDS = int(os.environ.get("AGENTAUTH_MCP_SESSION_TTL", "3600"))

# Capability resource prefix. Each authorized file is addressed as
# "<RESOURCE_PREFIX><relative/path>", e.g. "repo:swe_triage/parser.py".
RESOURCE_PREFIX = os.environ.get("AGENTAUTH_MCP_RESOURCE_PREFIX", "repo:")


# --- server ------------------------------------------------------------------- #
HOST = os.environ.get("AGENTAUTH_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("AGENTAUTH_MCP_PORT", os.environ.get("PORT", "8849")))
SERVER_NAME = "agentauth-gate"


def ensure_dirs() -> None:
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    GATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
