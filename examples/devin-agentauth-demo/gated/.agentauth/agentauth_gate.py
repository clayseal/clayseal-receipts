#!/usr/bin/env python3
"""Minimal AgentAuth PR gate for the Devin end-to-end demo."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

try:
    from agentauth.core.hash_util import hash_canonical_json, sha256_hex
    from agentauth.core.signing import (
        load_or_create_key,
        sign_bundle,
        verify as verify_signature,
        verify_bundle_signatures,
    )
    from agentauth.receipts.structural_invariants import (
        add_flag,
        add_reason,
        evaluate_build_integrity,
        evaluate_instruction_hygiene,
        evaluate_instruction_surfaces_at_head,
        evaluate_mandate_anomaly,
        evaluate_protected_invariants as _evaluate_protected_invariants,
        matches_any_path as matches_any,
        scan_obfuscation,
    )
    from agentauth.receipts.cross_session import (
        DEFAULT_POISON_MARKERS,
        discover_prior_session_artifacts,
        evaluate_cross_session_attribution,
    )
    from agentauth.receipts.receipt_chain import (
        link_receipt_chain_from_evidence,
        load_gate_receipts,
        verify_receipt_at_merge,
        verify_receipt_chain,
    )
except ImportError as exc:  # pragma: no cover - exercised in CI setup failures.
    raise SystemExit(
        "AgentAuth SDK is required. Install it first, for example: "
        "python -m pip install -e ./_agentauth_source"
    ) from exc

RECEIPT_SCHEMA = "agentauth.devin_pr_gate.receipt.v1"
AUTHORIZATION_SCHEMA = "agentauth.human_authorization.v1"


def read_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, value: dict[str, Any]) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dest


def file_sha256(path: str | Path) -> str:
    return sha256_hex(Path(path).read_bytes())


def run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        text=True,
        capture_output=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed with {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc


def parse_name_status(raw: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith(("R", "C")) and len(parts) >= 3:
            path = parts[2]
            old_path = parts[1]
        elif len(parts) >= 2:
            path = parts[1]
            old_path = None
        else:
            continue
        code = status[0]
        operation = {
            "A": "add",
            "M": "modify",
            "D": "delete",
            "R": "rename",
            "C": "copy",
        }.get(code, code.lower())
        changes.append(
            {"status": status, "operation": operation, "path": path, "old_path": old_path}
        )
    return changes


def parse_added_lines(diff: str) -> dict[str, list[str]]:
    added: dict[str, list[str]] = {}
    current: str | None = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            current = None if target == "/dev/null" else target.removeprefix("b/")
            if current is not None:
                added.setdefault(current, [])
            continue
        if current is not None and line.startswith("+") and not line.startswith("+++"):
            added[current].append(line[1:])
    return added


def show_file(repo: Path, ref: str, path: str) -> str:
    """Return the contents of ``path`` at git ``ref`` (empty if absent)."""
    proc = run_git(repo, "show", f"{ref}:{path}", check=False)
    return proc.stdout if proc.returncode == 0 else ""


def evaluate_protected_invariants(
    repo: Path,
    policy: dict[str, Any],
    changes: list[dict[str, Any]],
    *,
    merge_base: str,
    head_sha: str,
    reasons: list[dict[str, Any]],
) -> None:
    _evaluate_protected_invariants(
        policy,
        changes,
        file_at_ref=lambda ref, path: show_file(repo, ref, path),
        merge_base=merge_base,
        head_sha=head_sha,
        reasons=reasons,
    )


def verify_authorization(envelope: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    reasons: list[dict[str, Any]] = []
    document = envelope.get("document")
    signature = envelope.get("signature")
    if not isinstance(document, dict):
        add_reason(
            reasons,
            code="authorization_missing",
            message="authorization envelope is missing a document",
        )
        return {}, reasons
    if document.get("schema") != AUTHORIZATION_SCHEMA:
        add_reason(
            reasons,
            code="authorization_schema_mismatch",
            message=f"unsupported authorization schema: {document.get('schema')!r}",
        )
    if not isinstance(signature, dict) or not verify_signature(document, signature):
        add_reason(
            reasons,
            code="authorization_signature_invalid",
            message="human authorization signature is invalid or missing",
        )
    return document, reasons


def detect_egress_sandbox() -> tuple[list[str], str | None]:
    from agentauth.receipts.hermetic_runner import detect_egress_sandbox as _detect

    return _detect()


def run_required_tests(
    repo: Path,
    commands: list[str],
    timeout: int,
    *,
    sandbox_prefix: list[str] | None = None,
    bootstrap_policy: Any | None = None,
    artifact_guard_policy: Any | None = None,
) -> list[dict[str, Any]]:
    from agentauth.receipts.artifact_guard import ArtifactGuardPolicy, scan_and_redact_secrets
    from agentauth.receipts.bootstrap_sandbox import (
        BootstrapPolicy,
        build_command_attestation,
    )

    sandbox_prefix = sandbox_prefix or []
    bootstrap_policy = bootstrap_policy or BootstrapPolicy()
    artifact_guard_policy = artifact_guard_policy or ArtifactGuardPolicy()
    runs: list[dict[str, Any]] = []
    sandboxed = bool(sandbox_prefix)
    mechanism = "unshare" if sandboxed else None

    def _store_output(stdout: str, stderr: str) -> tuple[str, str, list[dict[str, Any]]]:
        scans: list[dict[str, Any]] = []
        if artifact_guard_policy.enabled and artifact_guard_policy.redact_logs:
            stdout_result = scan_and_redact_secrets(stdout)
            stderr_result = scan_and_redact_secrets(stderr)
            stdout = stdout_result.redacted_text
            stderr = stderr_result.redacted_text
            if stdout_result.findings:
                scans.append({"stream": "stdout", **stdout_result.to_dict()})
            if stderr_result.findings:
                scans.append({"stream": "stderr", **stderr_result.to_dict()})
        return stdout[-4000:], stderr[-4000:], scans

    for command in commands:
        try:
            proc = subprocess.run(
                [*sandbox_prefix, *shlex.split(command)],
                cwd=repo,
                check=False,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            stdout_tail, stderr_tail, secret_scans = _store_output(proc.stdout, proc.stderr)
            run: dict[str, Any] = {
                "command": command,
                "exit_code": proc.returncode,
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "stdout_sha256": sha256_hex(stdout_tail.encode("utf-8")),
                "stderr_sha256": sha256_hex(stderr_tail.encode("utf-8")),
            }
            if secret_scans:
                run["secret_scans"] = secret_scans
            if bootstrap_policy.enabled and bootstrap_policy.record_command_receipts:
                run["command_execution"] = build_command_attestation(
                    command,
                    cwd=str(repo),
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    exit_code=proc.returncode,
                    sandboxed=sandboxed,
                    sandbox_mechanism=mechanism,
                    env_allowlist=bootstrap_policy.env_allowlist,
                ).to_dict()
            runs.append(run)
        except subprocess.TimeoutExpired as exc:
            stdout_text = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr_text = exc.stderr if isinstance(exc.stderr, str) else ""
            stdout_tail, stderr_tail, secret_scans = _store_output(stdout_text, stderr_text)
            run = {
                "command": command,
                "exit_code": 124,
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "stdout_sha256": sha256_hex(stdout_tail.encode("utf-8")),
                "stderr_sha256": sha256_hex(stderr_tail.encode("utf-8")),
                "timed_out": True,
            }
            if secret_scans:
                run["secret_scans"] = secret_scans
            if bootstrap_policy.enabled and bootstrap_policy.record_command_receipts:
                run["command_execution"] = build_command_attestation(
                    command,
                    cwd=str(repo),
                    stdout=stdout_text,
                    stderr=stderr_text,
                    exit_code=124,
                    sandboxed=sandboxed,
                    sandbox_mechanism=mechanism,
                    env_allowlist=bootstrap_policy.env_allowlist,
                ).to_dict()
            runs.append(run)
    return runs


def issue_authorization(args: argparse.Namespace) -> int:
    document = read_json(args.template)
    key = load_or_create_key(args.key)
    envelope = {"document": document, "signature": key.sign(document)}
    write_json(args.out, envelope)
    print(f"wrote signed authorization: {args.out}")
    print(f"authorization commitment: {hash_canonical_json(document)}")
    return 0


def finalize_receipt(receipt: dict[str, Any], key_path: str | Path) -> dict[str, Any]:
    body_without_hash = {
        k: v for k, v in receipt.items() if k not in {"signatures", "receipt_hash"}
    }
    receipt["receipt_hash"] = hash_canonical_json(body_without_hash)
    key = load_or_create_key(key_path)
    sign_bundle(receipt, key, role="agentauth-pr-gate")
    return receipt


def resolve_oidc_identity(
    args: argparse.Namespace, policy: dict[str, Any], reasons: list[dict[str, Any]]
) -> None:
    """Verify optional OIDC token and bind actor claims onto ``args``."""
    token = (getattr(args, "oidc_token", None) or "").strip()
    actor_cfg = policy.get("actor_binding") if isinstance(policy.get("actor_binding"), dict) else {}
    if not token:
        if actor_cfg.get("require_verified_oidc"):
            add_reason(
                reasons,
                code="oidc_required",
                message=(
                    "policy requires a verified OIDC actor token "
                    "(GitHub Actions or configured JWKS issuer)"
                ),
            )
        return
    try:
        from agentauth.receipts.oidc_actor import resolve_verified_actor

        identity = resolve_verified_actor(
            token,
            jwks_url=(getattr(args, "oidc_jwks_url", None) or None),
            issuer=(getattr(args, "oidc_issuer", None) or None),
            audience=(getattr(args, "oidc_audience", None) or None),
        )
        args.oidc_subject = identity.oidc_subject
        args.oidc_issuer = identity.oidc_issuer
        if identity.github_actor:
            if args.github_actor and args.github_actor != identity.github_actor:
                add_reason(
                    reasons,
                    code="oidc_actor_mismatch",
                    message=(
                        f"OIDC actor {identity.github_actor!r} does not match "
                        f"--github-actor {args.github_actor!r}"
                    ),
                    evidence={
                        "oidc_actor": identity.github_actor,
                        "github_actor": args.github_actor,
                    },
                )
            elif not args.github_actor:
                args.github_actor = identity.github_actor
    except Exception as exc:
        add_reason(
            reasons,
            code="oidc_verification_failed",
            message=f"OIDC token verification failed: {exc}",
        )


def evaluate(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    policy = read_json(args.policy)
    authorization_envelope = read_json(args.authorization)
    authorization, reasons = verify_authorization(authorization_envelope)
    resolve_oidc_identity(args, policy, reasons)
    scope = authorization.get("scope", {})

    base_sha = head_sha = merge_base = name_status = unified_diff = numstat = ""
    try:
        base_sha = run_git(repo, "rev-parse", args.base).stdout.strip()
        head_sha = run_git(repo, "rev-parse", args.head).stdout.strip()
        merge_base = run_git(repo, "merge-base", args.base, args.head).stdout.strip()
        diff_range = f"{merge_base}..{head_sha}"
        name_status = run_git(repo, "diff", "--name-status", "--find-renames", diff_range).stdout
        unified_diff = run_git(repo, "diff", "--unified=0", "--no-ext-diff", diff_range).stdout
        numstat = run_git(repo, "diff", "--numstat", diff_range).stdout
    except Exception as exc:
        add_reason(
            reasons,
            code="diff_unavailable",
            message=f"failed closed because git diff could not be computed: {exc}",
        )

    changes = parse_name_status(name_status)
    added_lines = parse_added_lines(unified_diff)
    flags: list[dict[str, Any]] = []

    issue_text: str | None = None
    issue_scan_text: str | None = None
    if args.issue and Path(args.issue).exists():
        issue_text = Path(args.issue).read_text(encoding="utf-8")
        try:
            doc = json.loads(issue_text)
            issue_scan_text = (
                "\n".join(str(doc.get(k, "")) for k in ("title", "body"))
                if isinstance(doc, dict)
                else issue_text
            )
        except json.JSONDecodeError:
            issue_scan_text = issue_text

    horizon_ref = getattr(args, "horizon_ref", None) or (policy.get("trajectory") or {}).get(
        "horizon_ref"
    )
    horizon_sha = merge_base
    if horizon_ref and head_sha:
        try:
            horizon_sha = run_git(repo, "merge-base", horizon_ref, head_sha).stdout.strip()
        except Exception:
            try:
                horizon_sha = run_git(repo, "rev-parse", horizon_ref).stdout.strip()
            except Exception:
                horizon_sha = merge_base

    receipts_dir = Path(args.receipt).parent
    prior_gate_receipts = load_gate_receipts(receipts_dir, exclude=args.receipt)

    file_snapshots: dict[str, dict[str, str]] = {}
    for change in changes:
        old_path = change.get("old_path") or change["path"]
        for path in {change["path"], old_path}:
            if path in file_snapshots:
                continue
            file_snapshots[path] = {
                merge_base: show_file(repo, merge_base, path),
                head_sha: (
                    ""
                    if change["operation"] == "delete" and path == change["path"]
                    else show_file(repo, head_sha, path)
                ),
            }
    for path in ("AGENTS.md", "DELEGATION.md", ".devin/knowledge.md"):
        if path not in file_snapshots:
            file_snapshots[path] = {
                merge_base: show_file(repo, merge_base, path),
                head_sha: show_file(repo, head_sha, path),
            }

    from agentauth.receipts.gate_evaluate import evaluate_devin_pr_diff, merge_evaluation_into_gate
    from agentauth.receipts.structural_invariants import PrGateEvidence

    evidence = PrGateEvidence(
        gate_policy=policy,
        authorization=authorization,
        changes=changes,
        added_lines=added_lines,
        merge_base=merge_base,
        head_sha=head_sha,
        horizon_sha=horizon_sha,
        issue_text=issue_scan_text,
        github_actor=args.github_actor or None,
        oidc_subject=getattr(args, "oidc_subject", None),
        oidc_issuer=getattr(args, "oidc_issuer", None),
        file_snapshots=file_snapshots,
        prior_gate_receipts=prior_gate_receipts,
    )
    diff_eval = evaluate_devin_pr_diff(evidence)
    merge_evaluation_into_gate(diff_eval, reasons=reasons, flags=flags)

    from agentauth.receipts.actor_chain import actor_identity_block

    # Execute required_tests under egress isolation when available.
    from agentauth.receipts.hermetic_runner import (
        HermeticRunnerPolicy,
        detect_egress_sandbox,
        evaluate_test_execution_posture,
    )

    test_cfg = policy.get("test_execution", {})
    hermetic_policy = HermeticRunnerPolicy.from_test_execution_dict(test_cfg)
    commands = list(scope.get("required_tests", []))
    for violation in evaluate_test_execution_posture(
        policy=hermetic_policy, commands=commands
    ):
        add_reason(reasons, code="required_tests_unsandboxed", message=violation)
    sandbox_prefix, mechanism = detect_egress_sandbox()
    egress_isolated = bool(commands) and mechanism is not None
    from agentauth.receipts.artifact_guard import ArtifactGuardPolicy
    from agentauth.receipts.bootstrap_sandbox import BootstrapPolicy, evaluate_bootstrap_command

    bootstrap_policy = BootstrapPolicy.from_policy_dict(policy.get("bootstrap"))
    artifact_policy = ArtifactGuardPolicy.from_policy_dict(policy.get("artifact_guard"))
    test_runs: list[dict[str, Any]] = []
    if commands and not any(
        item.get("code") == "required_tests_unsandboxed" for item in reasons
    ):
        bootstrap_blocked = False
        for command in commands:
            for violation in evaluate_bootstrap_command(
                command,
                policy=bootstrap_policy,
                sandboxed=egress_isolated,
                sandbox_mechanism=mechanism,
            ):
                bootstrap_blocked = True
                add_reason(
                    reasons,
                    code="bootstrap_command_denied",
                    message=violation,
                    evidence={"command": command},
                )
        if not bootstrap_blocked:
            test_runs = run_required_tests(
                repo,
                commands,
                args.test_timeout,
                sandbox_prefix=sandbox_prefix,
                bootstrap_policy=bootstrap_policy,
                artifact_guard_policy=artifact_policy,
            )
            for run in test_runs:
                if run["exit_code"] != 0:
                    add_reason(
                        reasons,
                        code="required_tests_failed",
                        message=f"required test command failed: {run['command']}",
                        evidence={"exit_code": run["exit_code"]},
                    )
    test_execution = {
        "commands": commands,
        "egress_isolated": egress_isolated,
        "sandbox_mechanism": mechanism,
        "require_egress_isolation": hermetic_policy.require_egress_isolation,
        "hermetic_python": hermetic_policy.require_hermetic_python,
        "ran": bool(test_runs) or not commands,
    }

    issue_block: dict[str, Any] | None = None
    if issue_text is not None:
        markers = [
            marker
            for marker in policy.get("poison_markers", [])
            if marker.lower() in issue_text.lower()
        ]
        issue_block = {
            "path": str(Path(args.issue).resolve()),
            "sha256": sha256_hex(issue_text.encode("utf-8")),
            "poison_markers_observed": markers,
        }

    outcome = "deny" if reasons else ("allow_with_review" if flags else "allow")
    receipt_id = f"rcpt_{uuid4().hex}"
    raw_markers = policy.get("poison_markers") or []
    marker_tuple = tuple(
        dict.fromkeys([*DEFAULT_POISON_MARKERS, *(str(item) for item in raw_markers)])
    )
    chain_links = link_receipt_chain_from_evidence(
        changes=changes,
        prior_receipts=prior_gate_receipts,
        receipt_id=receipt_id,
        markers=marker_tuple,
    )

    from agentauth.receipts.ci_context import (
        CiContextPolicy,
        ci_context_block,
        normalize_ci_source,
        validate_ci_context,
    )
    from agentauth.receipts.context_provenance import (
        ProvenanceSurface,
        build_context_provenance,
    )

    ci_sources: list[dict[str, Any]] = [
        normalize_ci_source("git_diff", unified_diff, ref=f"{merge_base}..{head_sha}"),
        normalize_ci_source("mandate", hash_canonical_json(authorization)),
        normalize_ci_source("policy", file_sha256(args.policy)),
    ]
    if issue_text is not None:
        ci_sources.append(
            normalize_ci_source("issue_template", issue_text, ref=str(args.issue or ""))
        )
    ci_policy = CiContextPolicy.from_policy_dict(policy.get("ci_context"))
    for violation in validate_ci_context(ci_sources, policy=ci_policy):
        add_reason(reasons, code="ci_context_violation", message=violation)
    if reasons:
        outcome = "deny"

    provenance_surfaces = [
        ProvenanceSurface("git_diff", f"{merge_base}..{head_sha}", sha256_hex(unified_diff.encode("utf-8")), trusted=True),
        ProvenanceSurface("mandate", hash_canonical_json(authorization)[:16], hash_canonical_json(authorization), trusted=True),
    ]
    if issue_text is not None:
        provenance_surfaces.append(
            ProvenanceSurface(
                "issue_template",
                str(args.issue or ""),
                sha256_hex(issue_text.encode("utf-8")),
                trusted=True,
            )
        )

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "decision": {
            "outcome": outcome,
            "fail_closed": outcome == "deny",
            "reason_count": len(reasons),
            "flag_count": len(flags),
            "review_required": bool(flags) and not reasons,
        },
        "agent": {
            "provider": authorization.get("agent", {}).get("provider", "cognition-devin"),
            "github_actor": args.github_actor,
            "claimed_workload": "devin/autonomous-coding-agent",
        },
        "actor_identity": actor_identity_block(
            github_actor=args.github_actor or None,
            oidc_subject=getattr(args, "oidc_subject", None),
            oidc_issuer=getattr(args, "oidc_issuer", None),
        ),
        "human_authorization": {
            "path": str(Path(args.authorization).resolve()),
            "commitment": hash_canonical_json(authorization),
            "document": authorization,
            "signature": authorization_envelope.get("signature"),
        },
        "policy": {
            "path": str(Path(args.policy).resolve()),
            "sha256": file_sha256(args.policy),
            "policy_id": policy.get("policy_id"),
        },
        "git": {
            "repo": str(repo),
            "base_ref": args.base,
            "base_sha": base_sha,
            "head_ref": args.head,
            "head_sha": head_sha,
            "evaluated_head_sha": head_sha,
            "merge_base": merge_base,
            "evaluated_merge_base": merge_base,
            "diff_hash": sha256_hex(unified_diff.encode("utf-8")),
            "changed_files": changes,
            "numstat": numstat.splitlines(),
        },
        "issue": issue_block,
        "test_runs": test_runs,
        "test_execution": test_execution,
        "evaluations": reasons,
        "flags": flags,
        "receipt_chain": {
            "prior_receipt_refs": [
                {
                    "receipt_id": item.get("receipt_id"),
                    "receipt_hash": item.get("receipt_hash"),
                }
                for item in prior_gate_receipts
                if item.get("receipt_id") and item.get("receipt_hash")
            ],
            "links": [link.to_dict() for link in chain_links],
        },
        "ci_context": ci_context_block(ci_sources),
        "context_provenance": build_context_provenance(
            provenance_surfaces,
            receipt_id=receipt_id,
        ),
        "trajectory": {
            "prior_receipt_count": len(prior_gate_receipts),
            "horizon_ref": getattr(args, "horizon_ref", None)
            or (policy.get("trajectory") or {}).get("horizon_ref"),
        },
    }
    finalize_receipt(receipt, args.key)
    write_json(args.receipt, receipt)

    print(f"AgentAuth Devin gate: {outcome.upper()}")
    print(f"receipt: {args.receipt}")
    print(f"receipt_hash: {receipt['receipt_hash']}")
    for reason in reasons:
        location = f" [{reason['path']}]" if reason.get("path") else ""
        print(f"- {reason['code']}{location}: {reason['message']}")
    for flag in flags:
        location = f" [{flag['path']}]" if flag.get("path") else ""
        print(f"~ {flag['code']}{location}: {flag['message']}")
    return 0 if outcome != "deny" else 1


def verify_receipt_value(receipt: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    signatures = receipt.get("signatures", [])
    expected_hash = hash_canonical_json(
        {k: v for k, v in receipt.items() if k not in {"signatures", "receipt_hash"}}
    )
    if receipt.get("receipt_hash") != expected_hash:
        issues.append("receipt_hash does not match receipt body")
    if not isinstance(signatures, list):
        issues.append("receipt signatures section is invalid")
        signatures = []
    trusted_public_keys = {
        sig.get("public_key") for sig in signatures if isinstance(sig, dict) and sig.get("public_key")
    }
    signature_check = verify_bundle_signatures(
        receipt,
        trusted_public_keys={str(item) for item in trusted_public_keys},
    )
    if not signature_check["valid"]:
        issues.extend(f"receipt signature invalid: {reason}" for reason in signature_check["reasons"])

    authorization = receipt.get("human_authorization")
    if not isinstance(authorization, dict):
        issues.append("human_authorization section is missing")
    else:
        document = authorization.get("document")
        auth_signature = authorization.get("signature")
        if not isinstance(document, dict) or not isinstance(auth_signature, dict):
            issues.append("human authorization document/signature is missing")
        elif not verify_signature(document, auth_signature):
            issues.append("human authorization signature is invalid")
        elif authorization.get("commitment") != hash_canonical_json(document):
            issues.append("human authorization commitment does not match document")

    evaluations = receipt.get("evaluations", [])
    reason_count = receipt.get("decision", {}).get("reason_count")
    if isinstance(evaluations, list) and reason_count != len(evaluations):
        issues.append("decision.reason_count does not match evaluations")

    return {
        "valid": not issues,
        "receipt_id": receipt.get("receipt_id"),
        "receipt_hash": receipt.get("receipt_hash"),
        "decision": receipt.get("decision", {}).get("outcome"),
        "issues": issues,
        "signer_key_ids": [
            sig.get("key_id") for sig in signatures if isinstance(sig, dict) and sig.get("key_id")
        ],
    }


def verify_receipt_command(args: argparse.Namespace) -> int:
    receipt = read_json(args.receipt)
    result = verify_receipt_value(receipt)
    if getattr(args, "merge_head", None):
        merge_result = verify_receipt_at_merge(
            receipt,
            merge_head_sha=args.merge_head,
            repo=getattr(args, "repo", None),
        )
        result["toctou"] = merge_result
        if not merge_result["valid"]:
            result["valid"] = False
            result["issues"].extend(merge_result["issues"])
    if getattr(args, "check_chain", False):
        priors = load_gate_receipts(Path(args.receipt).parent, exclude=args.receipt)
        chain_result = verify_receipt_chain(receipt, priors)
        result["receipt_chain"] = chain_result
        if not chain_result["valid"]:
            result["valid"] = False
            result["issues"].extend(chain_result["issues"])
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"receipt verification: {'VALID' if result['valid'] else 'INVALID'}")
        print(f"receipt_id: {result['receipt_id']}")
        print(f"receipt_hash: {result['receipt_hash']}")
        print(f"decision: {result['decision']}")
        for issue in result["issues"]:
            print(f"- {issue}")
    return 0 if result["valid"] else 1


def verify_merge_command(args: argparse.Namespace) -> int:
    receipt = read_json(args.receipt)
    result = verify_receipt_at_merge(
        receipt,
        merge_head_sha=args.merge_head,
        repo=args.repo,
    )
    base = verify_receipt_value(receipt)
    if not base["valid"]:
        result["valid"] = False
        result["issues"] = [*base["issues"], *result["issues"]]
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"merge verification: {'VALID' if result['valid'] else 'INVALID'}")
        print(f"evaluated_head_sha: {result.get('evaluated_head_sha')}")
        print(f"merge_head_sha: {result.get('merge_head_sha')}")
        for issue in result["issues"]:
            print(f"- {issue}")
    return 0 if result["valid"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    auth = sub.add_parser("issue-authorization", help="sign a human authorization document")
    auth.add_argument("--template", required=True)
    auth.add_argument("--key", required=True)
    auth.add_argument("--out", required=True)
    auth.set_defaults(func=issue_authorization)

    evaluate_parser = sub.add_parser("evaluate", help="evaluate a Devin PR diff")
    evaluate_parser.add_argument("--repo", required=True)
    evaluate_parser.add_argument("--base", required=True)
    evaluate_parser.add_argument("--head", required=True)
    evaluate_parser.add_argument("--authorization", required=True)
    evaluate_parser.add_argument("--policy", required=True)
    evaluate_parser.add_argument("--issue")
    evaluate_parser.add_argument("--receipt", required=True)
    evaluate_parser.add_argument("--key", required=True)
    evaluate_parser.add_argument("--github-actor", default="")
    evaluate_parser.add_argument(
        "--oidc-token",
        default="",
        help="OIDC JWT from CI (e.g. GitHub Actions id-token); verified against JWKS",
    )
    evaluate_parser.add_argument(
        "--oidc-jwks-url",
        default="",
        help="Override JWKS URL (default: GitHub Actions well-known JWKS)",
    )
    evaluate_parser.add_argument("--oidc-issuer", default="", help="Override expected JWT iss")
    evaluate_parser.add_argument("--oidc-audience", default="", help="Require JWT aud claim")
    evaluate_parser.add_argument(
        "--horizon-ref",
        default=None,
        help="Stable branch/ref for trajectory invariant checks (default: policy.trajectory.horizon_ref)",
    )
    evaluate_parser.add_argument("--test-timeout", type=int, default=60)
    evaluate_parser.set_defaults(func=evaluate)

    verify_parser = sub.add_parser("verify-receipt", help="verify a signed gate receipt")
    verify_parser.add_argument("--receipt", required=True)
    verify_parser.add_argument("--merge-head", help="fail if receipt was not evaluated at this SHA (GATE-4)")
    verify_parser.add_argument("--repo", help="optional repo path for diff_hash re-check")
    verify_parser.add_argument("--check-chain", action="store_true", help="verify receipt-chain links")
    verify_parser.add_argument("--json", action="store_true")
    verify_parser.set_defaults(func=verify_receipt_command)

    merge_parser = sub.add_parser("verify-merge", help="verify receipt binding to merge commit SHA")
    merge_parser.add_argument("--receipt", required=True)
    merge_parser.add_argument("--merge-head", required=True)
    merge_parser.add_argument("--repo")
    merge_parser.add_argument("--json", action="store_true")
    merge_parser.set_defaults(func=verify_merge_command)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
