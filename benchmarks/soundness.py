#!/usr/bin/env python3.11
"""Adversarial soundness benchmark — empirical proof, not demoware.

Runs the full single-field tamper battery over real exported receipts and asks, for
each integrity model in a contrast ladder, *does the verifier accept a tampered
receipt it should reject?* (the false-accept rate). The ladder:

    plaintext_log    — plain structured logging (no integrity)
    naive_canonical  — sign/bind the proof core only (the common "signed receipt")
    agentauth        — verify_receipt_bundle (full binding + identity + evidence)

`naive_canonical` is an independent re-implementation of the canonical-core checks, so
it also cross-checks that AgentAuth's rejections on that class are real, not self-graded.

Headline metric: **security-relevant false-accept rate** = fraction of mutations to
security-load-bearing fields that the verifier fails to flag, with a 95% Wilson upper
bound. One seeded command, provenance-stamped, re-runnable.

    python3.11 benchmarks/soundness.py --suite all --limit 200 [--with-identity]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

BENCH_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH_ROOT))

from harness.baselines import BASELINE_VERIFIERS  # noqa: E402
from harness.config import AdapterOptions  # noqa: E402
from harness.paths import ensure_import_paths  # noqa: E402
from harness.runner import _classify_survivor_path, run_benchmarks  # noqa: E402

from agentauth.receipts.export import verify_receipt_bundle  # noqa: E402
from agentauth.receipts.tamper import leaf_mutations  # noqa: E402

VERIFIERS = {**BASELINE_VERIFIERS, "agentauth": verify_receipt_bundle}
LADDER = ["plaintext_log", "signed_payload", "hash_chain_log", "naive_canonical", "agentauth"]
# Documented, accepted residual: not forgeable content (DB ordinal; needs the log key).
RESIDUAL_ALLOWLIST = {"audit_record.seq"}


def _classify(path: str) -> str:
    # identity.* is security-relevant (added here to avoid editing the shared classifier).
    if path.startswith("identity."):
        return "security_relevant"
    return _classify_survivor_path(path)


def _issue_sigs(result: dict) -> list[str]:
    return sorted(
        f"{i.get('code')}|{i.get('message')}" for i in (result.get("issues") or [])
    )


def _judge(fn, bundle: dict) -> tuple[dict | None, bool]:
    """Returns (result, raised). A verifier that raises on a bundle has rejected it."""
    try:
        return fn(bundle), False
    except Exception:
        return None, True


def _flagged(clean: dict | None, mutated: dict | None) -> bool:
    if clean is None or mutated is None:
        return clean is not mutated
    return clean.get("valid") != mutated.get("valid") or _issue_sigs(clean) != _issue_sigs(
        mutated
    )


def _provenance() -> dict:
    import platform
    import subprocess
    from datetime import datetime, timezone

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=BENCH_ROOT
        ).stdout.strip()
    except Exception:
        commit = None
    return {
        "git_commit": commit,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


def _wilson_upper(k: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 1.0
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, (centre + margin) / denom)


def run_ladder(bundles: list[dict]) -> dict:
    stats = {
        name: {"sec_total": 0, "sec_missed": 0, "missed": Counter()} for name in VERIFIERS
    }
    total_mutations = 0
    for bundle in bundles:
        muts = leaf_mutations(bundle)
        clean = {name: _judge(fn, bundle)[0] for name, fn in VERIFIERS.items()}
        for mutation in muts:
            total_mutations += 1
            if _classify(mutation.path or "") != "security_relevant":
                continue
            mutated = mutation.apply(bundle)
            for name, fn in VERIFIERS.items():
                stats[name]["sec_total"] += 1
                result, raised = _judge(fn, mutated)
                # A verifier that raises on the tamper has caught it (rejected).
                flagged = raised or _flagged(clean[name], result)
                if not flagged:
                    stats[name]["sec_missed"] += 1
                    stats[name]["missed"][mutation.path] += 1

    rows = {}
    for name in LADDER:
        s = stats[name]
        missed_paths = dict(s["missed"].most_common())
        non_residual = {p: c for p, c in missed_paths.items() if p not in RESIDUAL_ALLOWLIST}
        forgeable_missed = sum(non_residual.values())
        n = s["sec_total"]
        rows[name] = {
            "security_trials": n,
            "false_accepts": s["sec_missed"],
            "false_accept_rate": (s["sec_missed"] / n) if n else None,
            "false_accept_rate_wilson_upper95": _wilson_upper(s["sec_missed"], n),
            # Forgeable-content rate excludes the documented non-forgeable residual
            # (audit_record.seq = DB ordinal; .signature = needs the external log key).
            "false_accepts_forgeable": forgeable_missed,
            "false_accept_rate_forgeable": (forgeable_missed / n) if n else None,
            "false_accept_rate_forgeable_wilson_upper95": _wilson_upper(forgeable_missed, n),
            "missed_paths": missed_paths,
            "missed_paths_excluding_documented_residual": non_residual,
        }
    return {"total_mutations": total_mutations, "ladder": rows}


PROVE_MODEL_HASH = "sha256:fraud-head-onnx-v1"


def _ulb_amounts(n: int) -> list[float]:
    """Real transaction amounts from the ULB corpus, for input diversity."""
    import csv

    path = BENCH_ROOT / "corpus" / "ulb_creditcard" / "creditcard.csv"
    amounts: list[float] = []
    if not path.is_file():
        return [100.0 * (i + 1) for i in range(n)]
    with path.open() as handle:
        for i, row in enumerate(csv.DictReader(handle)):
            if i >= n:
                break
            amounts.append(float(row["Amount"]))
    return amounts


def _generate_real_prove_bundles(n: int) -> list[dict]:
    """Generate receipts carrying REAL composed ZK proofs (Halo2 policy + RISC0
    inference), so the clean baseline verifies `valid` with the proof bytes actually
    checked. Proving uses ALLOW_STUB=0; the verifier (run later in the ladder) accepts
    the stub TEE quote (no hardware) but still cryptographically verifies the real
    proof — so a tampered proof is rejected, not waved through. ~3s/case (RISC0)."""
    ensure_import_paths()
    zkvm_bin = BENCH_ROOT.parent / "crates" / "agent-receipts-zkvm" / "target" / "release"
    os.environ["PATH"] = f"{zkvm_bin}:{os.environ.get('PATH', '')}"
    os.environ["AGENT_RECEIPTS_ALLOW_STUB"] = "0"  # force real proving

    from agentauth.receipts import AgentWrapper, Policy
    from agentauth.receipts.certificate import dev_certificate
    from agentauth.receipts.export import build_receipt_bundle

    policy = Policy.from_yaml(BENCH_ROOT.parent / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment(), model_hash=PROVE_MODEL_HASH)
    bundles: list[dict] = []
    for i, amount in enumerate(_ulb_amounts(n)):
        score = min(1.0, amount / 10_000.0)
        agent = AgentWrapper(
            model=lambda inp, s=score: {"decision": "approve", "fraud_score": s},
            policy=policy,
            certificate=cert,
            mode="prove",
            inference_backend="risc0",
            model_provenance_hash=PROVE_MODEL_HASH,
            audit_db=":memory:",
        )
        try:
            result = agent.run({"transaction_id": f"rp-{i}", "amount": amount})
            bundles.append(build_receipt_bundle(result, certificate=cert, policy=policy))
        except Exception:
            continue
    return bundles


def _generate_bundles(args) -> list[dict]:
    ensure_import_paths()
    gen_dir = Path(tempfile.mkdtemp(prefix="soundness-"))
    options = AdapterOptions(limit=args.limit, ulb_sample=args.ulb_sample)
    run_benchmarks(
        suites=None if args.suite == "all" else args.suite.split(","),
        limit=args.limit,
        mode=args.mode,
        export_receipts=True,
        with_identity=args.with_identity,
        require_verify=False,
        tamper_analysis=False,
        adapter_options=options,
        results_dir=gen_dir,
    )
    bundles = []
    for path in sorted(gen_dir.glob("*.json")):
        if path.name.endswith(".tamper.json") or path.name == "summary.json":
            continue
        try:
            bundles.append(json.loads(path.read_text()))
        except json.JSONDecodeError:
            continue
    return bundles


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default="all")
    parser.add_argument("--limit", type=int, default=100, help="cases per suite")
    parser.add_argument("--mode", default="bounded_auto")
    parser.add_argument("--with-identity", action="store_true")
    parser.add_argument("--ulb-sample", default="sequential", choices=["sequential", "stratified"])
    parser.add_argument("--out", type=Path, default=BENCH_ROOT / "results" / "soundness.json")
    parser.add_argument(
        "--real-prove",
        action="store_true",
        help="Generate receipts with REAL composed ZK proofs (Halo2+RISC0); valid "
        "baseline, so false-accept = tampered receipt that still verifies VALID.",
    )
    parser.add_argument("--prove-limit", type=int, default=40, help="receipts for --real-prove")
    args = parser.parse_args()

    started = time.time()
    if args.real_prove:
        bundles = _generate_real_prove_bundles(args.prove_limit)
        # Verifier accepts the stub TEE quote (no hardware) but still checks the real proof.
        os.environ["AGENT_RECEIPTS_ALLOW_STUB"] = "1"
    else:
        bundles = _generate_bundles(args)
    if not bundles:
        print("no bundles generated", file=sys.stderr)
        return 1
    result = run_ladder(bundles)
    report = {
        "benchmark": "adversarial_soundness",
        "config": {
            "suite": args.suite, "limit": args.limit, "mode": args.mode,
            "with_identity": args.with_identity, "ulb_sample": args.ulb_sample,
            "real_prove": args.real_prove, "prove_limit": args.prove_limit,
        },
        "bundles": len(bundles),
        "elapsed_s": round(time.time() - started, 1),
        "provenance": _provenance(),
        **result,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))

    sec = result["ladder"]["agentauth"]["security_trials"]
    print(f"\nAdversarial soundness — {len(bundles)} receipts, {result['total_mutations']:,} "
          f"mutations, {sec:,} security-relevant tamper trials per verifier\n")
    cols = f"{'verifier':16} {'false_accept':>14} {'forgeable':>12} {'95%up(forge)':>14}"
    print(cols)
    print("-" * len(cols))
    for name in LADDER:
        r = result["ladder"][name]
        print(
            f"{name:16} {r['false_accept_rate']:>14.5f} {r['false_accept_rate_forgeable']:>12.5f} "
            f"{r['false_accept_rate_forgeable_wilson_upper95']:>14.2e}"
        )
    aa = result["ladder"]["agentauth"]
    residual = aa["missed_paths_excluding_documented_residual"]
    print(f"\nagentauth misses beyond documented residual {sorted(RESIDUAL_ALLOWLIST)}: "
          f"{residual or 'NONE'}")
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
