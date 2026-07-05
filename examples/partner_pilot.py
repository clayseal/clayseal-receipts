#!/usr/bin/env python3
"""
Design partner pilot: preflight, stable certificate, run, export receipt.

  cp config/partner.example.yaml config/partner.yaml
  arctl preflight config/partner.yaml
  python3 examples/partner_pilot.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentauth.receipts.export import export_run_result  # noqa: E402
from agentauth.receipts.logging_config import setup_logging  # noqa: E402
from agentauth.receipts.partner_config import PartnerConfig  # noqa: E402
from agentauth.receipts.partner_factory import build_agent_from_config  # noqa: E402
from agentauth.receipts.policy import Policy  # noqa: E402
from agentauth.receipts.preflight import run_preflight  # noqa: E402

CONFIG = ROOT / "config" / "partner.yaml"
RECEIPTS_DIR = ROOT / "receipts"
log = setup_logging()


def main() -> None:
    if not CONFIG.is_file():
        log.error("Missing %s — copy config/partner.example.yaml", CONFIG)
        sys.exit(1)

    report = run_preflight(CONFIG)
    if not report["go"]:
        log.error("Preflight failed: %s", report["blocking_failures"])
        sys.exit(1)
    if report["warnings"]:
        log.warning("Preflight warnings: %s", report["warnings"])

    cfg = PartnerConfig.from_yaml(CONFIG)
    policy = Policy.from_yaml(cfg.policy_path)

    def model(inp: dict) -> dict:
        amount = float(inp.get("amount", 0))
        score = min(1.0, amount / 10_000.0)
        decision = "deny" if score > 0.8 else "review" if score > 0.4 else "approve"
        return {"decision": decision, "fraud_score": round(score, 4)}

    agent = build_agent_from_config(cfg, model)
    inp = {"transaction_id": "partner-pilot-1", "amount": 1800.0}
    result = agent.run(inp)

    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RECEIPTS_DIR / f"{result.proof.proof_id}.json"
    export_run_result(
        out,
        result,
        certificate=agent.certificate,
        policy=policy,
        policy_path=cfg.policy_path,
        context={"input": inp},
    )

    log.info("output=%s violations=%s", result.output, result.policy_violations)
    log.info("verification=%s", result.proof.verify())
    log.info("receipt=%s", out)
    agent.audit.verify_chain()
    log.info("audit records=%s", len(agent.audit))


if __name__ == "__main__":
    main()
