#!/usr/bin/env python3.11
"""Prove-tier characterization (EV-201/202).

Measures the assurance-tier backends head to head: prove time, verify time, proof
size, and — the property that matters for a *verifiable* system — tamper-resistance
(mutate the proof, the verifier must reject it). Backends:

  * halo2_policy  — Halo2 range-policy proof over fraud_score (main CLI)
  * risc0_inference — RISC Zero fraud-head zkVM proof
  * sp1_inference   — SP1 (Plonky3) fraud-head zkVM proof (same computation as risc0)

Each row is **measured here**, skipped cleanly if its binary isn't built. Run:
    python3.11 scripts/prove_tier_matrix.py [--out results/prove_tier.json]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "target" / "release" / "agent-receipts"
RISC0 = ROOT / "crates" / "agent-receipts-zkvm" / "target" / "release" / "agent-receipts-zkvm"
SP1 = ROOT / "crates" / "agent-receipts-sp1" / "target" / "release" / "agent-receipts-sp1"

AMOUNT, OUTPUT_HASH, MODEL_HASH = "25000", "bench-output-hash", "sha256:fraud-head-v1"


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str, float]:
    start = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr, (time.perf_counter() - start) * 1000


def _flip_hex(hexstr: str) -> str:
    c = hexstr[0]
    return ("f" if c != "f" else "0") + hexstr[1:]


def zkvm_row(name: str, binary: Path, json_key: str, flag: str, timeout: int) -> dict | None:
    if not binary.is_file():
        return {"backend": name, "status": "skipped (binary not built)"}
    rc, out, err, prove_wall = _run(
        [str(binary), "prove", "--amount", AMOUNT, "--output-hash", OUTPUT_HASH,
         "--model-provenance-hash", MODEL_HASH, "--json"], timeout)
    if rc != 0:
        return {"backend": name, "status": f"prove failed: {err.strip()[:120]}"}
    rep = json.loads(out)
    verify_base = [
        str(binary), "verify", f"--{flag}", rep[json_key],
        "--amount", AMOUNT, "--output-hash", OUTPUT_HASH,
        "--model-provenance-hash", MODEL_HASH, "--score", str(rep["score"]),
    ]
    vrc, _vo, _ve, verify_wall = _run(verify_base + ["--receipt-hex", rep["receipt_hex"]], timeout)
    # Tamper: flip a byte of the proof; verifier must reject.
    trc, _to, _te, _tw = _run(
        verify_base + ["--receipt-hex", _flip_hex(rep["receipt_hex"])], timeout)
    return {
        "backend": name,
        "status": "ok",
        "prove_ms_reported": rep.get("prove_ms"),
        "prove_ms_wall": round(prove_wall),
        "verify_ms_wall": round(verify_wall),
        "proof_bytes": rep.get("receipt_bytes"),
        "verify_accepts_valid": vrc == 0,
        "verify_rejects_tampered": trc != 0,
    }


def halo2_policy_row(timeout: int) -> dict | None:
    if not MAIN.is_file():
        return {"backend": "halo2_policy", "status": "skipped (binary not built)"}
    out_file = ROOT / "target" / "_prove_tier_policy.json"
    rc, _o, err, prove_wall = _run(
        [str(MAIN), "prove-policy", "--score", "0.25", "--policy-commitment", "pc-bench",
         "--output-hash", OUTPUT_HASH, "--out", str(out_file)], timeout)
    if rc != 0:
        return {"backend": "halo2_policy", "status": f"prove failed: {err.strip()[:120]}"}
    proof_bytes = out_file.stat().st_size
    vrc, _vo, _ve, verify_wall = _run(
        [str(MAIN), "verify-policy", "--envelope", str(out_file)], timeout)
    # Tamper: flip the first char of the longest string field (the proof) and verify.
    envelope = json.loads(out_file.read_text())
    longest_key = max((k for k in envelope if isinstance(envelope[k], str)),
                      key=lambda k: len(envelope[k]))
    envelope[longest_key] = _flip_hex(envelope[longest_key])
    tampered = ROOT / "target" / "_prove_tier_policy_tampered.json"
    tampered.write_text(json.dumps(envelope))
    trc, _to, _te, _tw = _run([str(MAIN), "verify-policy", "--envelope", str(tampered)], timeout)
    return {
        "backend": "halo2_policy",
        "status": "ok",
        "prove_ms_wall": round(prove_wall),
        "verify_ms_wall": round(verify_wall),
        "proof_bytes": proof_bytes,
        "verify_accepts_valid": vrc == 0,
        "verify_rejects_tampered": trc != 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, default=ROOT / "benchmarks" / "results" / "prove_tier.json"
    )
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()

    rows = [
        halo2_policy_row(args.timeout),
        zkvm_row("risc0_inference", RISC0, "image_id", "image-id", args.timeout),
        zkvm_row("sp1_inference", SP1, "image_id", "vk-hash", args.timeout),
    ]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"prove_tier_matrix": rows}, indent=2))

    hdr = (
        f"{'backend':16} {'prove_ms':>9} {'verify_ms':>10} {'proof_bytes':>12} "
        f"{'accepts':>8} {'rejects_tamper':>15}"
    )
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        if r.get("status") != "ok":
            print(f"{r['backend']:16} {r.get('status')}")
            continue
        print(
            f"{r['backend']:16} {r.get('prove_ms_wall',''):>9} {r.get('verify_ms_wall',''):>10} "
            f"{r.get('proof_bytes',''):>12} {str(r['verify_accepts_valid']):>8} "
            f"{str(r['verify_rejects_tampered']):>15}"
        )
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
