#!/usr/bin/env python3
"""Generate curated demo artifacts D-01 through D-08 for partners and auditors."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BENCHMARKS_ROOT.parent
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.paths import ensure_import_paths  # noqa: E402
from harness.pipeline import BenchmarkPipeline, PipelineConfig, fraud_policy  # noqa: E402
from harness.runner import run_benchmarks  # noqa: E402
from harness.adapters.registry import iter_cases  # noqa: E402
from harness.config import AdapterOptions  # noqa: E402

DEFAULT_OUT = BENCHMARKS_ROOT / "demo" / "output"
ULB_DEMO_CASE = "ulb_000000"
MODEL_HASH = "sha256:fraud-head-onnx-v1"


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def _bundle_to_ecs(bundle: dict[str, Any], *, timestamp: str | None = None) -> dict[str, Any]:
    authority = bundle.get("authority") or {}
    proof = bundle.get("execution_proof") or {}
    verification = bundle.get("verification") or {}
    ts = timestamp or datetime.now(UTC).isoformat()
    output = bundle.get("output") or {}
    return {
        "@timestamp": ts,
        "event.kind": "event",
        "event.category": ["process"],
        "event.type": ["info"],
        "event.action": (proof.get("execution_context") or {}).get("action_name", "agent.run"),
        "event.outcome": "allow" if output.get("decision") != "deny" else "deny",
        "agent.id": authority.get("subject_id") or authority.get("workload_principal"),
        "agent.version": bundle.get("schema_version", "0.2.1"),
        "rule.name": authority.get("policy_name"),
        "rule.uuid": authority.get("policy_commitment"),
        "session.id": proof.get("session_id"),
        "user.id": authority.get("subject_id"),
        "hash.sha256": proof.get("output_hash"),
        "agent_receipts": {
            "proof_id": proof.get("proof_id"),
            "schema": bundle.get("schema"),
            "context_hash": proof.get("context_hash"),
            "output_hash": proof.get("output_hash"),
            "policy_commitment": authority.get("policy_commitment"),
            "model_provenance_hash": authority.get("model_provenance_hash"),
            "assurance_level": (bundle.get("assurance") or {}).get("level"),
            "assurance_tier": (bundle.get("assurance") or {}).get("tier"),
            "verification_valid": verification.get("valid"),
            "verification_issue_count": len(verification.get("reasons") or []),
        },
    }


def _run_suite_export(
    *,
    suite: str,
    out_dir: Path,
    limit: int = 1,
    mode: str = "bounded_auto",
    with_identity: bool = False,
    inference_backend: str = "ezkl",
) -> Path:
    report = run_benchmarks(
        suites=[suite],
        limit=limit,
        mode=mode,  # type: ignore[arg-type]
        export_receipts=True,
        with_identity=with_identity,
        inference_backend=inference_backend,
        results_dir=out_dir,
    )
    case = report.cases[0]
    receipt = case.metadata.get("receipt_path")
    if not receipt:
        raise RuntimeError(f"{suite} export missing receipt_path")
    return Path(receipt)


def _run_ulb_mode(*, mode: str, out_dir: Path, prove: bool = False) -> dict[str, Any]:
    cases = list(iter_cases("ulb_fraud", limit=1, options=AdapterOptions()))
    if not cases:
        raise RuntimeError("ULB corpus missing; run scripts/download_benchmark_corpora.sh")
    case = cases[0]
    config = PipelineConfig(
        mode=mode,  # type: ignore[arg-type]
        export_receipts=True,
        results_dir=out_dir,
        model_provenance_hash=MODEL_HASH if mode == "prove" else "sha256:model-dev-v1",
        inference_backend="ezkl",
    )
    pipeline = BenchmarkPipeline(fraud_policy(), config=config)
    result = pipeline.run_case(case)
    receipt_path = result.metadata.get("receipt_path")
    bundle = json.loads(Path(receipt_path).read_text()) if receipt_path else {}
    return {
        "mode": mode,
        "case_id": case.case_id,
        "ok": result.ok,
        "verify_valid": result.verify_valid,
        "latency_ms": result.latency_ms,
        "receipt_path": receipt_path,
        "proof_bytes": result.metadata.get("total_proof_bytes"),
        "bundle_assurance": (bundle.get("assurance") or {}),
    }


def generate_d01(out: Path) -> dict[str, Any]:
    """5-minute product demo: single ULB receipt + walkthrough script."""
    d01 = out / "D-01_quickstart"
    receipt = _run_suite_export(suite="ulb_fraud", out_dir=d01 / "run", limit=1)
    walkthrough = d01 / "WALKTHROUGH.md"
    walkthrough.write_text(
        f"""# D-01 — 5-minute product demo

## Receipt
- Bundle: `{receipt.name}`
- Source: ULB creditcard row 0 via fraud policy pipeline

## Walkthrough (5 min)
1. Open the receipt JSON — point out `execution_proof`, `authority`, `output`.
2. Run structural verify:
   ```bash
   python -c "from agentauth.receipts.export import verify_receipt_bundle; import json; b=json.load(open('{receipt}')); print(verify_receipt_bundle(b))"
   ```
3. Show audit chain fields in `audit_record` (hash-linked append-only log).
4. Contrast with `examples/01_quickstart.py` for live AgentAuth identity issuance.
5. Optional dashboard: load bundle into receipt viewer / compliance ingest preview.
"""
    )
    return {"receipt": str(receipt), "walkthrough": str(walkthrough)}


def generate_d02(out: Path) -> dict[str, Any]:
    """MCP + prove: composed verifiable bundle (harness replay; live path in examples/)."""
    d02 = out / "D-02_mcp_prove"
    import os

    os.environ.setdefault("AGENT_RECEIPTS_ALLOW_STUB", "1")
    receipt = _run_suite_export(
        suite="ulb_fraud",
        out_dir=d02 / "run",
        limit=1,
        mode="prove",
    )
    note = d02 / "README.md"
    note.write_text(
        f"""# D-02 — MCP live + prove

This bundle was generated in **prove mode** with composed policy+inference proofs
(same assurance tier as `examples/mcp_live_prove_client.py`).

- **Harness bundle:** `{receipt.name}`
- **Live MCP path:** `python examples/mcp_live_prove_client.py stdio`
  (requires `cargo build -p agent-receipts-cli --release` and `AGENT_RECEIPTS_ALLOW_STUB=1` for stub proofs)

Verify:
```bash
AGENT_RECEIPTS_ALLOW_STUB=1 python -c "from agentauth.receipts.export import verify_receipt_bundle; import json; print(verify_receipt_bundle(json.load(open('{receipt}'))))"
```
"""
    )
    return {"receipt": str(receipt), "live_example": "examples/mcp_live_prove_client.py"}


def generate_d03(out: Path) -> dict[str, Any]:
    """Partner pilot story with fixed inputs."""
    d03 = out / "D-03_partner_pilot"
    from agentauth.receipts import AgentWrapper
    from agentauth.receipts.certificate import dev_certificate
    from agentauth.receipts.export import build_receipt_bundle
    from agentauth.receipts.inference import amount_to_score
    import tempfile

    policy = fraud_policy()
    amount = 2500.0
    score = amount_to_score(amount)
    audit_path = Path(tempfile.mkdtemp(prefix="demo-pilot-")) / "audit.sqlite"
    agent = AgentWrapper(
        model=lambda inp: {
            "decision": "approve",
            "fraud_score": amount_to_score(float(inp["amount"])),
        },
        policy=policy,
        certificate=dev_certificate(policy.commitment()),
        mode="bounded_auto",
        audit_db=str(audit_path),
    )
    result = agent.run({"transaction_id": "pilot-demo-001", "amount": amount}, session_id="pilot-demo")
    bundle = build_receipt_bundle(result, certificate=agent.certificate, policy=policy)
    receipt = d03 / "partner_pilot_receipt.json"
    _write_json(receipt, bundle)
    script = d03 / "STORY.md"
    script.write_text(
        f"""# D-03 — Partner pilot story

Fixed transaction: **${amount:,.2f}** → fraud_score **{score:.4f}** → decision **approve**.

1. Partner runs preflight (`examples/partner_pilot.py` / `config/partner.yaml`).
2. Agent executes fraud policy with stable certificate.
3. Receipt exported: `{receipt.name}`
4. Auditor verifies bundle offline — no trust in partner logs.

Full script: `python examples/partner_pilot.py`
"""
    )
    return {"receipt": str(receipt), "amount": amount, "fraud_score": score}


def generate_d04(out: Path) -> dict[str, Any]:
    """BFCL capability block: allowed tool succeeds, decoy blocked."""
    d04 = out / "D-04_capability_block"
    report = run_benchmarks(
        suites=["bfcl_caps"],
        limit=1,
        export_receipts=True,
        results_dir=d04 / "run",
    )
    case = report.cases[0]
    meta = case.metadata
    readme = d04 / "README.md"
    readme.write_text(
        f"""# D-04 — Capability allowlist block

Case `{case.case_id}`: tool **{meta.get('allowed_tool')}** allowed; **decoy_tool** blocked.

- `decoy_blocked`: {meta.get('decoy_blocked')}
- Policy violations on decoy should cite allowlist.

The exported receipt captures the **allowed** tool call. The decoy block is recorded
in case metadata and audit chain (see harness `bfcl_caps` adapter).
"""
    )
    return {
        "case_id": case.case_id,
        "allowed_tool": meta.get("allowed_tool"),
        "decoy_blocked": meta.get("decoy_blocked"),
        "receipt": case.metadata.get("receipt_path"),
    }


def generate_d05(out: Path) -> dict[str, Any]:
    """Identity + receipt on 3 ATIF agents."""
    d05 = out / "D-05_identity_atif"
    report = run_benchmarks(
        suites=["atif_mcp"],
        limit=3,
        export_receipts=True,
        with_identity=True,
        results_dir=d05 / "run",
    )
    receipts = [c.metadata.get("receipt_path") for c in report.cases if c.metadata.get("receipt_path")]
    readme = d05 / "README.md"
    readme.write_text(
        """# D-05 — Identity-bound receipts (ATIF)

Three MCP trajectory replays with `--with-identity`:
- SPIFFE ID in `authority.workload_principal`
- JWT-SVID + issuer JWKS in `identity` section
- Offline identity verify + live validate at 1.0 in harness metrics

Compare bundles — each should show distinct embedded credentials per bootstrap tenant.
"""
    )
    return {"receipts": receipts, "passed": sum(1 for c in report.cases if c.ok)}


def generate_d06(out: Path) -> dict[str, Any]:
    """Auditor packet: 10-bundle zip + verify commands."""
    d06 = out / "D-06_auditor_packet"
    run_dir = d06 / "bundles"
    report = run_benchmarks(
        suites=["ulb_fraud", "atif_mcp", "bfcl_caps"],
        limit=4,
        export_receipts=True,
        results_dir=run_dir,
    )
    receipts = [
        Path(c.metadata["receipt_path"])
        for c in report.cases
        if c.metadata.get("receipt_path")
    ][:10]
    zip_path = d06 / "auditor_packet_10.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in receipts:
            zf.write(path, arcname=path.name)
    verify_readme = d06 / "VERIFY.md"
    lines = [
        "# D-06 — Auditor packet\n",
        f"Zip: `{zip_path.name}` ({len(receipts)} bundles)\n",
        "## Verify each bundle\n",
        "```bash",
    ]
    for path in receipts:
        lines.append(
            f'python -c "from agentauth.receipts.export import verify_receipt_bundle; '
            f'import json; b=json.load(open(\'{path.name}\')); print(b.get(\'schema\'), verify_receipt_bundle(b)[\'valid\'])"'
        )
    lines.append("```")
    verify_readme.write_text("\n".join(lines) + "\n")
    return {"zip": str(zip_path), "bundle_count": len(receipts)}


def generate_d07(out: Path) -> dict[str, Any]:
    """Compliance ingest: ECS events from 5 receipts."""
    ensure_import_paths()
    from agentauth.receipts.compliance import export_siem_ecs

    d07 = out / "D-07_compliance_ingest"
    report = run_benchmarks(
        suites=["ulb_fraud"],
        limit=5,
        export_receipts=True,
        results_dir=d07 / "run",
    )
    events = []
    for case in report.cases:
        path = case.metadata.get("receipt_path")
        if not path:
            continue
        bundle = json.loads(Path(path).read_text())
        events.append(export_siem_ecs(bundle))
    events_path = d07 / "ecs_events.jsonl"
    events_path.parent.mkdir(parents=True, exist_ok=True)
    with events_path.open("w") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
    fixture = REPO_ROOT / "compliance" / "fixtures" / "ecs_ingest_sample.json"
    if fixture.is_file():
        shutil.copy(fixture, d07 / "ecs_ingest_sample.json")
    readme = d07 / "README.md"
    readme.write_text(
        f"""# D-07 — Compliance / SIEM ingest

- `{events_path.name}` — {len(events)} ECS-shaped events from ULB receipt bundles
- `ecs_ingest_sample.json` — reference fixture from `compliance/fixtures/`

Pipe into your SIEM parser or OpenSearch ingest pipeline for schema validation.
"""
    )
    return {"events": str(events_path), "count": len(events)}


def generate_d08(out: Path) -> dict[str, Any]:
    """Assurance ladder: same ULB row across shadow → bounded_auto → prove."""
    import os

    os.environ.setdefault("AGENT_RECEIPTS_ALLOW_STUB", "1")
    d08 = out / "D-08_assurance_ladder"
    ladder = []
    for mode in ("shadow", "bounded_auto", "prove"):
        row = _run_ulb_mode(mode=mode, out_dir=d08 / mode)
        ladder.append(row)
    comparison = {
        "case_id": ULB_DEMO_CASE,
        "modes": ladder,
        "summary": {
            mode["mode"]: {
                "verify_valid": mode["verify_valid"],
                "assurance": mode.get("bundle_assurance"),
                "proof_bytes": mode.get("proof_bytes"),
            }
            for mode in ladder
        },
    }
    _write_json(d08 / "comparison.json", comparison)
    one_pager = d08 / "ASSURANCE_LADDER.md"
    one_pager.write_text(
        """# D-08 — Assurance ladder (same ULB transaction)

| Mode | Tier | verify_valid | Notes |
|------|------|--------------|-------|
| shadow | declared | false (no TEE) | Fastest; audit chain only |
| bounded_auto | operator_attested | false (no TEE) | Policy + audit binding |
| prove | composed_proved | **true** (with stub/real prover) | Cryptographic verify |

See `comparison.json` and per-mode receipt bundles in subfolders.
"""
    )
    return comparison


GENERATORS = {
    "D-01": generate_d01,
    "D-02": generate_d02,
    "D-03": generate_d03,
    "D-04": generate_d04,
    "D-05": generate_d05,
    "D-06": generate_d06,
    "D-07": generate_d07,
    "D-08": generate_d08,
}


def generate_all(out_dir: Path, *, only: list[str] | None = None) -> dict[str, Any]:
    ensure_import_paths()
    out_dir.mkdir(parents=True, exist_ok=True)
    selected = only or list(GENERATORS.keys())
    manifest: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "output_dir": str(out_dir),
        "sets": {},
    }
    for demo_id in selected:
        if demo_id not in GENERATORS:
            raise SystemExit(f"Unknown demo set {demo_id!r}")
        manifest["sets"][demo_id] = GENERATORS[demo_id](out_dir)
    _write_json(out_dir / "manifest.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate demo sets D-01 through D-08")
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output directory (default: benchmarks/demo/output)",
    )
    parser.add_argument(
        "--only",
        default="",
        help="Comma-separated demo IDs (e.g. D-01,D-08). Default: all",
    )
    args = parser.parse_args()
    only = [part.strip() for part in args.only.split(",") if part.strip()] or None
    manifest = generate_all(args.out, only=only)
    print(json.dumps(manifest, indent=2))
    print(f"\nDemo sets written to {args.out}")


if __name__ == "__main__":
    main()
