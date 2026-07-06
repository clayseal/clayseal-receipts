"""Agent Receipts CLI — demos, diagnostics, and receipt verification."""

from __future__ import annotations

import argparse
import json
import runpy
import sys
from pathlib import Path
from typing import Any

from agentauth.receipts.audit import (
    AuditChain,
    checkpoint_trust_issues,
    required_audit_witnesses_from_env,
    trusted_audit_log_policy_from_env,
    trusted_audit_witness_keys_from_env,
)
from agentauth.receipts.auditor import auditor_evidence_summary
from agentauth.receipts.diagnostics import run_diagnostics
from agentauth.receipts.explain import explain_receipt_bundle
from agentauth.receipts.export import (
    export_bundle_for_audience,
    load_receipt_bundle,
    verify_receipt_bundle,
    write_receipts_ndjson,
)
from agentauth.receipts.partner_config import PartnerConfig
from agentauth.receipts.policy import Policy
from agentauth.receipts.preflight import run_preflight
from agentauth.receipts.replay import re_evaluate_policy_decision
from agentauth.core.signing import load_or_create_key


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def cmd_preflight(args: argparse.Namespace) -> int:
    report = run_preflight(args.config, strict=args.strict)
    print(json.dumps(report, indent=2))
    return 0 if report["go"] else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    report = run_diagnostics(require_prover=args.require_prover)
    print(json.dumps(report, indent=2))
    return 0 if report["ready"] else 1


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    bundle = load_receipt_bundle(args.bundle)
    kwargs: dict[str, Any] = {"min_assurance_tier": args.min_assurance_tier}
    if getattr(args, "require_identity_binding", False):
        kwargs["require_identity_binding"] = True
    result = verify_receipt_bundle(bundle, **kwargs)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


def cmd_explain(args: argparse.Namespace) -> int:
    bundle = load_receipt_bundle(args.bundle)
    report = explain_receipt_bundle(bundle)
    print(json.dumps(report, indent=2))
    return 0


def cmd_format_bundle(args: argparse.Namespace) -> int:
    bundle = load_receipt_bundle(args.bundle)
    if args.profile:
        formatted = export_bundle_for_audience(bundle, profile=args.profile)
        mode = f"profile:{args.profile}"
    else:
        mode = "redacted" if args.redacted else ("compact" if args.compact else "full")
        formatted = export_bundle_for_audience(bundle, mode=mode)
    out = args.out or args.bundle
    if args.cbor:
        from agentauth.receipts.export import write_receipt_bundle_cbor

        cbor_out = out if out.suffix.lower() == ".cbor" else out.with_suffix(".cbor")
        write_receipt_bundle_cbor(cbor_out, formatted if isinstance(formatted, dict) else bundle)
        print(f"canonical CBOR receipt written to {cbor_out}")
        return 0
    if isinstance(formatted, str):
        out.write_text(formatted + "\n", encoding="utf-8")
    else:
        out.write_text(json.dumps(formatted, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"formatted ({mode}) receipt written to {out}")
    return 0


def cmd_export_tiles(args: argparse.Namespace) -> int:
    from agentauth.receipts import tiles

    key = load_or_create_key(args.signing_key) if args.signing_key else None
    chain = AuditChain(args.audit_db, signing_key=key)
    chain.verify_chain()
    files = chain.static_log_tiles(args.origin, key_name=args.key_name)
    tiles.write_static_log(files, args.out)
    print(f"exported {len(files)} static log files to {args.out}")
    return 0


def cmd_verify_tiles(args: argparse.Namespace) -> int:
    from agentauth.receipts import tiles

    files = tiles.load_static_log(args.tiles_dir)
    leaf = bytes.fromhex(args.leaf)
    ok = tiles.verify_leaf_in_static_log(files, leaf)
    print(json.dumps({"valid": ok, "leaf": args.leaf}, indent=2))
    return 0 if ok else 1


def cmd_audit_summary(args: argparse.Namespace) -> int:
    bundle = load_receipt_bundle(args.bundle)
    summary = auditor_evidence_summary(
        bundle,
        profile=args.profile,
        siem_format=args.siem_format,
    )
    if isinstance(summary, str):
        print(summary)
    else:
        print(json.dumps(summary, indent=2))
    return 0


def cmd_replay_check(args: argparse.Namespace) -> int:
    bundle = load_receipt_bundle(args.bundle)
    policy = Policy.from_yaml(args.policy)
    report = re_evaluate_policy_decision(bundle, policy)
    print(json.dumps(report, indent=2))
    return 0 if report["match"] else 1


def cmd_export_audit(args: argparse.Namespace) -> int:
    chain = AuditChain(args.audit_db)
    chain.verify_chain()
    count = chain.export_jsonl(args.out)
    print(f"exported {count} records to {args.out}")
    return 0


def cmd_audit_by_mandate(args: argparse.Namespace) -> int:
    from agentauth.receipts.audit import audit_record_to_dict

    chain = AuditChain(args.audit_db)
    records = chain.records_for_mandate_ref(args.ref)
    payload = [audit_record_to_dict(record) for record in records]
    print(json.dumps({"ref": args.ref, "count": len(payload), "records": payload}, indent=2))
    return 0


def _resolve_record_hash(chain: AuditChain, args: argparse.Namespace) -> str:
    if args.seq is not None:
        for rec in chain.iter_records():
            if rec.seq == args.seq:
                return rec.record_hash
        raise SystemExit(f"no audit record with seq {args.seq}")
    if not args.record:
        raise SystemExit("audit-prove requires --record <hash> or --seq <n>")
    return args.record


def cmd_audit_prove(args: argparse.Namespace) -> int:
    chain = AuditChain(args.audit_db)
    chain.verify_chain()
    record_hash = _resolve_record_hash(chain, args)
    try:
        proof = chain.inclusion_proof(record_hash)
    except KeyError as exc:
        raise SystemExit(str(exc)) from None
    checkpoint = chain.signed_checkpoint()
    verified = AuditChain.verify_inclusion(record_hash, proof, checkpoint)
    out = {"inclusion_proof": proof, "checkpoint": checkpoint, "verified": verified}
    payload = json.dumps(out, indent=2, sort_keys=True)
    if args.out is not None:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
        print(f"wrote inclusion proof for {record_hash} to {args.out} (verified={verified})")
    else:
        print(payload)
    return 0 if verified else 1


def cmd_audit_consistency(args: argparse.Namespace) -> int:
    signing_key = None
    signing_key_path = getattr(args, "signing_key", None)
    if signing_key_path is not None:
        if not signing_key_path.is_file():
            print(
                json.dumps(
                    {
                        "verified": False,
                        "trust_verified": False,
                        "trust_issues": [
                            f"signing key file not found: {signing_key_path}"
                        ],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 2
        signing_key = load_or_create_key(signing_key_path)

    chain = AuditChain(args.audit_db, signing_key=signing_key)
    chain.verify_chain()
    new_size = args.new_size if args.new_size is not None else len(chain)
    proof = chain.consistency_proof(args.old_size, new_size)
    new_checkpoint = chain.signed_checkpoint()
    out: dict = {"consistency_proof": proof, "new_checkpoint": new_checkpoint}
    if args.old_checkpoint is not None:
        old_checkpoint = json.loads(Path(args.old_checkpoint).read_text(encoding="utf-8"))
        log_policy = trusted_audit_log_policy_from_env()
        trust_configured = bool(log_policy["public_keys"] or log_policy["key_ids"])
        required_witnesses = 0
        trusted_witnesses: set[str] | None = None
        if trust_configured:
            required_witnesses = required_audit_witnesses_from_env()
            trusted_witnesses = trusted_audit_witness_keys_from_env()
        verified = AuditChain.verify_consistency(
            old_checkpoint,
            new_checkpoint,
            proof,
            trusted_log_public_keys=(
                log_policy["public_keys"] if trust_configured else None
            ),
            trusted_log_key_ids=log_policy["key_ids"] if trust_configured else None,
            required_witnesses=required_witnesses,
            trusted_witness_keys=trusted_witnesses,
        )
        out["verified"] = verified
        trust_issues: list[str] = []
        if trust_configured:
            trust_issues.extend(
                checkpoint_trust_issues(
                    old_checkpoint,
                    trusted_public_keys=log_policy["public_keys"],
                    trusted_key_ids=log_policy["key_ids"],
                    required_witnesses=required_witnesses,
                    trusted_witness_keys=trusted_witnesses,
                )
            )
            trust_issues.extend(
                checkpoint_trust_issues(
                    new_checkpoint,
                    trusted_public_keys=log_policy["public_keys"],
                    trusted_key_ids=log_policy["key_ids"],
                    required_witnesses=required_witnesses,
                    trusted_witness_keys=trusted_witnesses,
                )
            )
            if trust_issues:
                out["trust_verified"] = False
                out["trust_issues"] = trust_issues
            else:
                out["trust_verified"] = True
        print(json.dumps(out, indent=2, sort_keys=True))
        if not verified:
            return 1
        if trust_issues:
            return 1
        return 0
    print(json.dumps(out, indent=2, sort_keys=True))
    return 2


def cmd_export_ndjson(args: argparse.Namespace) -> int:
    bundles = [load_receipt_bundle(path) for path in args.bundles]
    write_receipts_ndjson(args.out, bundles)
    print(f"exported {len(bundles)} receipt(s) to {args.out}")
    return 0


def cmd_show_config(args: argparse.Namespace) -> int:
    cfg = PartnerConfig.from_yaml(args.config)
    print(json.dumps(
        {
            "policy_path": str(cfg.policy_path),
            "audit_db": str(cfg.audit_db),
            "mode": cfg.mode,
            "certificate_path": str(cfg.certificate_path) if cfg.certificate_path else None,
            "model_provenance_hash": cfg.model_provenance_hash,
        },
        indent=2,
    ))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import ssl as _ssl

    from agentauth.receipts.verifier_auth import validate_verifier_bind
    from agentauth.receipts.verifier_server import get_app, require_verifier_deps

    require_verifier_deps()
    validate_verifier_bind(args.host)
    import uvicorn

    ssl_kwargs: dict = {}
    if args.tls_cert:
        ssl_kwargs["ssl_certfile"] = str(args.tls_cert)
    if args.tls_key:
        ssl_kwargs["ssl_keyfile"] = str(args.tls_key)
    if args.tls_ca:
        ssl_kwargs["ssl_ca_certs"] = str(args.tls_ca)
        ssl_kwargs["ssl_cert_reqs"] = _ssl.CERT_REQUIRED

    uvicorn.run(get_app(), host=args.host, port=args.port, log_level=args.log_level, **ssl_kwargs)
    return 0


def cmd_redact(args: argparse.Namespace) -> int:
    from agentauth.receipts.redact import redact_receipt_bundle

    bundle = load_receipt_bundle(args.bundle)
    redacted = redact_receipt_bundle(bundle, fields=args.fields)
    out = args.out or args.bundle
    out.write_text(json.dumps(redacted, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"redacted receipt written to {out}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    examples = {
        "shadow_fraud": "shadow_fraud_agent.py",
        "mcp_live": "mcp_live_client.py",
        "mcp_prove": "mcp_live_prove_client.py",
    }
    name = args.example
    if name not in examples:
        print(f"unknown example: {name}", file=sys.stderr)
        return 2
    path = _repo_root() / "examples" / examples[name]
    runpy.run_path(str(path), run_name="__main__")
    return 0


def cmd_run_agent(args: argparse.Namespace) -> int:
    from agentauth.receipts.repo_agent.terminal import run_terminal

    return run_terminal(
        repo=args.repo,
        secured=args.receipts,
        both=args.both,
        pause=args.pause,
        show_commands=args.show_commands,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Agent Receipts — design partner tooling",
    )
    sub = parser.add_subparsers(dest="command")

    preflight = sub.add_parser("preflight", help="Go/no-go checks before partner deployment")
    preflight.add_argument("config", type=Path, nargs="?", default="config/partner.yaml")
    preflight.add_argument("--strict", action="store_true", help="Enforce production placeholders")
    preflight.set_defaults(func=cmd_preflight)

    doctor = sub.add_parser("doctor", help="Check environment readiness")
    doctor.add_argument(
        "--require-prover",
        action="store_true",
        help="Fail if Rust CLI or proving keys are missing",
    )
    doctor.set_defaults(func=cmd_doctor)

    verify = sub.add_parser("verify-bundle", help="Verify an exported receipt JSON file")
    verify.add_argument("bundle", type=Path, help="Path to receipt bundle JSON")
    verify.add_argument(
        "--min-assurance-tier",
        default=None,
        help="Require at least this trust tier (e.g. signed, zk_policy_proved)",
    )
    verify.add_argument(
        "--require-identity-binding",
        action="store_true",
        help="Reject receipts lacking a validated attested-identity binding",
    )
    verify.set_defaults(func=cmd_verify_bundle)

    explain = sub.add_parser("explain", help="Human-readable explanation of a receipt bundle")
    explain.add_argument("bundle", type=Path, help="Path to receipt bundle JSON")
    explain.set_defaults(func=cmd_explain)

    fmt = sub.add_parser("format-bundle", help="Compact or redact a receipt bundle for export")
    fmt.add_argument("bundle", type=Path, help="Path to receipt bundle JSON")
    fmt.add_argument("--out", type=Path, default=None, help="Output path (default: overwrite)")
    fmt.add_argument("--compact", action="store_true", help="Strip verbose fields")
    fmt.add_argument("--redacted", action="store_true", help="Redact sensitive fields")
    fmt.add_argument(
        "--profile",
        choices=["eu-ai-act", "soc2", "iso27001"],
        default=None,
        help="Compliance profile mapped export",
    )
    fmt.add_argument(
        "--cbor",
        action="store_true",
        help="Write canonical CBOR artifact (.cbor) instead of JSON",
    )
    fmt.set_defaults(func=cmd_format_bundle)

    audit = sub.add_parser("audit-summary", help="Compliance-facing summary of a receipt bundle")
    audit.add_argument("bundle", type=Path)
    audit.add_argument(
        "--profile",
        choices=["eu-ai-act", "soc2", "iso27001"],
        default=None,
        help="Map receipt to a compliance control profile",
    )
    audit.add_argument(
        "--siem-format",
        choices=["ecs", "otel", "cef"],
        default=None,
        help="Emit SIEM-native record (ECS, OTel, or CEF) instead of summary JSON",
    )
    audit.set_defaults(func=cmd_audit_summary)

    replay = sub.add_parser(
        "replay-check",
        help="Re-run software policy on a stored receipt and compare to stored decision",
    )
    replay.add_argument("bundle", type=Path)
    replay.add_argument(
        "--policy",
        type=Path,
        default=Path("policies/fraud_decision.yaml"),
        help="Policy YAML used for re-evaluation",
    )
    replay.set_defaults(func=cmd_replay_check)

    export = sub.add_parser("export-audit", help="Export audit chain as JSONL")
    export.add_argument("--audit-db", type=Path, required=True)
    export.add_argument("--out", type=Path, required=True)
    export.set_defaults(func=cmd_export_audit)

    audit_by_mandate = sub.add_parser(
        "audit-by-mandate",
        help="List audit records indexed by mandate_ref or token_ref (SOTA-16d)",
    )
    audit_by_mandate.add_argument("--audit-db", type=Path, required=True)
    audit_by_mandate.add_argument(
        "--ref",
        required=True,
        help="mandate_ref or token_ref hex (SHA-256 of mandate document)",
    )
    audit_by_mandate.set_defaults(func=cmd_audit_by_mandate)

    prove = sub.add_parser(
        "audit-prove",
        help="Emit a Merkle inclusion proof + signed checkpoint for one audit record",
    )
    prove.add_argument("--audit-db", type=Path, required=True)
    prove.add_argument("--record", help="Record hash (leaf) to prove inclusion of")
    prove.add_argument("--seq", type=int, default=None, help="Audit record sequence number")
    prove.add_argument("--out", type=Path, default=None, help="Write proof JSON here")
    prove.set_defaults(func=cmd_audit_prove)

    cons = sub.add_parser(
        "audit-consistency",
        help="Emit an append-only consistency proof from an earlier size to now",
    )
    cons.add_argument("--audit-db", type=Path, required=True)
    cons.add_argument("--old-size", type=int, required=True, help="Earlier log size (count)")
    cons.add_argument("--new-size", type=int, default=None, help="Newer size (default: current)")
    cons.add_argument(
        "--old-checkpoint",
        type=Path,
        default=None,
        help="Earlier signed checkpoint JSON; if given, verifies the proof",
    )
    cons.add_argument(
        "--signing-key",
        type=Path,
        default=None,
        help="Ed25519 PEM private key used to sign the newly emitted checkpoint",
    )
    cons.set_defaults(func=cmd_audit_consistency)

    tiles_export = sub.add_parser(
        "export-tiles",
        help="Export audit log as C2SP tlog-tiles static files (SOTA-14)",
    )
    tiles_export.add_argument("--audit-db", type=Path, required=True)
    tiles_export.add_argument("--origin", required=True, help="C2SP checkpoint origin name")
    tiles_export.add_argument("--out", type=Path, required=True, help="Output directory")
    tiles_export.add_argument(
        "--signing-key",
        type=Path,
        default=None,
        help="Ed25519 PEM for checkpoint signing (required unless chain has a key)",
    )
    tiles_export.add_argument(
        "--key-name",
        default=None,
        help="C2SP note signer name (defaults to origin)",
    )
    tiles_export.set_defaults(func=cmd_export_tiles)

    tiles_verify = sub.add_parser(
        "verify-tiles",
        help="Verify a leaf is included in an exported static log",
    )
    tiles_verify.add_argument("--tiles-dir", type=Path, required=True)
    tiles_verify.add_argument("--leaf", required=True, help="Leaf hash hex (audit record_hash)")
    tiles_verify.set_defaults(func=cmd_verify_tiles)

    ndjson = sub.add_parser(
        "export-ndjson",
        help="Combine one or more receipt JSON files into NDJSON",
    )
    ndjson.add_argument("bundles", type=Path, nargs="+", help="Receipt bundle JSON paths")
    ndjson.add_argument("--out", type=Path, required=True, help="Output NDJSON path")
    ndjson.set_defaults(func=cmd_export_ndjson)

    cfg = sub.add_parser("show-config", help="Print resolved partner YAML paths")
    cfg.add_argument("config", type=Path, help="Path to partner config YAML")
    cfg.set_defaults(func=cmd_show_config)

    serve = sub.add_parser("serve", help="Start HTTP receipt verifier (POST /v1/verify)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--log-level", default="info")
    serve.add_argument("--tls-cert", type=Path, default=None, help="Server TLS certificate PEM")
    serve.add_argument("--tls-key", type=Path, default=None, help="Server TLS private key PEM")
    serve.add_argument(
        "--tls-ca",
        type=Path,
        default=None,
        help="CA bundle PEM for verifying client certificates (enables mTLS)",
    )
    serve.set_defaults(func=cmd_serve)

    redact = sub.add_parser("redact", help="Redact PII fields in a receipt bundle for sharing")
    redact.add_argument("bundle", type=Path)
    redact.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output path (default: overwrite input)",
    )
    redact.add_argument(
        "--fields",
        nargs="*",
        default=None,
        help="Extra dot-path fields to redact",
    )
    redact.set_defaults(func=cmd_redact)

    demo = sub.add_parser("demo", help="Run a bundled example script")
    demo.add_argument(
        "example",
        nargs="?",
        default="shadow_fraud",
        choices=["shadow_fraud", "mcp_live", "mcp_prove"],
    )
    demo.set_defaults(func=cmd_demo)

    run_agent = sub.add_parser(
        "run-agent",
        help="Run a coding agent against a repository (comparison fixture)",
    )
    run_agent.add_argument(
        "--repo",
        default="examples/poisoned-repo",
        help="Repository path (default: examples/poisoned-repo)",
    )
    run_agent.add_argument(
        "--receipts",
        action="store_true",
        help="Enforce tool allowlist and emit verifiable receipts",
    )
    run_agent.add_argument(
        "--both",
        action="store_true",
        help="Run unsecured then receipts mode in one terminal (rehearsal)",
    )
    run_agent.add_argument(
        "--pause",
        type=float,
        default=0.0,
        help="Seconds between steps when printing to terminal",
    )
    run_agent.add_argument(
        "--show-commands",
        action="store_true",
        help="Print shell commands for a two-pane live presentation",
    )
    run_agent.set_defaults(func=cmd_run_agent)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(2)
    # Fail closed before running any command if a production process sets a
    # soundness-downgrading escape hatch (no-op outside AGENT_RECEIPTS_ENV=production).
    from agentauth.receipts.environment import enforce_production_soundness

    enforce_production_soundness()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
