#!/usr/bin/env python3
"""AgentAuth gate for Devin-created pull requests.

This is intentionally CI-shaped: it evaluates a real git diff between a base ref and
a head ref, compares it to a signed human authorization, writes a signed receipt,
and exits 0 on allow / 1 on deny.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentauth.core.hash_util import hash_canonical_json, sha256_hex  # noqa: E402
from agentauth.core.signing import load_or_create_key  # noqa: E402
from agentauth.core.signing import verify as verify_signature  # noqa: E402

RECEIPT_SCHEMA = "agentauth.devin_pr_gate.receipt.v1"
AUTHORIZATION_SCHEMA = "agentauth.human_authorization.v1"


@dataclass
class GitChange:
    status: str
    path: str
    old_path: str | None = None

    @property
    def operation(self) -> str:
        code = self.status[0]
        if code == "A":
            return "add"
        if code == "M":
            return "modify"
        if code == "D":
            return "delete"
        if code == "R":
            return "rename"
        if code == "C":
            return "copy"
        return code.lower()

    def to_dict(self) -> dict[str, str | None]:
        return {
            "status": self.status,
            "operation": self.operation,
            "path": self.path,
            "old_path": self.old_path,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def parse_name_status(raw: str) -> list[GitChange]:
    changes: list[GitChange] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith("R") or status.startswith("C"):
            if len(parts) < 3:
                continue
            changes.append(GitChange(status=status, old_path=parts[1], path=parts[2]))
        elif len(parts) >= 2:
            changes.append(GitChange(status=status, path=parts[1]))
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


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def add_reason(
    reasons: list[dict[str, Any]],
    *,
    code: str,
    message: str,
    severity: str = "error",
    path: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> None:
    reasons.append(
        {
            "code": code,
            "severity": severity,
            "message": message,
            "path": path,
            "evidence": evidence or {},
        }
    )


def sign_document(document: dict[str, Any], key_path: Path) -> dict[str, Any]:
    key = load_or_create_key(key_path)
    return {"document": document, "signature": key.sign(document)}


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


def receipt_signing_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in receipt.items() if k not in {"signature"}}


def finalize_receipt(receipt: dict[str, Any], key_path: Path) -> dict[str, Any]:
    body_without_hash = {
        k: v for k, v in receipt.items() if k not in {"signature", "receipt_hash"}
    }
    receipt["receipt_hash"] = hash_canonical_json(body_without_hash)
    key = load_or_create_key(key_path)
    receipt["signature"] = key.sign(receipt_signing_payload(receipt))
    return receipt


def verify_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    signature = receipt.get("signature")
    authorization = receipt.get("human_authorization", {})
    expected_hash = hash_canonical_json(
        {k: v for k, v in receipt.items() if k not in {"signature", "receipt_hash"}}
    )
    if receipt.get("receipt_hash") != expected_hash:
        issues.append("receipt_hash does not match receipt body")
    if not isinstance(signature, dict) or not verify_signature(
        receipt_signing_payload(receipt), signature
    ):
        issues.append("receipt signature is invalid")
    if not isinstance(authorization, dict):
        issues.append("human_authorization section is missing")
    else:
        auth_document = authorization.get("document")
        auth_signature = authorization.get("signature")
        if not isinstance(auth_document, dict) or not isinstance(auth_signature, dict):
            issues.append("human authorization document/signature is missing")
        elif not verify_signature(auth_document, auth_signature):
            issues.append("human authorization signature is invalid")
        elif authorization.get("commitment") != hash_canonical_json(auth_document):
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
        "signer_key_id": signature.get("key_id") if isinstance(signature, dict) else None,
    }


def issue_authorization(args: argparse.Namespace) -> int:
    document = read_json(args.template)
    envelope = sign_document(document, Path(args.key))
    write_json(args.out, envelope)
    print(f"wrote signed authorization: {args.out}")
    print(f"authorization commitment: {hash_canonical_json(document)}")
    return 0


def run_required_tests(repo: Path, commands: list[str], timeout: int) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for command in commands:
        try:
            proc = subprocess.run(
                shlex.split(command),
                cwd=repo,
                check=False,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            stdout = proc.stdout[-4000:]
            stderr = proc.stderr[-4000:]
            runs.append(
                {
                    "command": command,
                    "exit_code": proc.returncode,
                    "stdout_tail": stdout,
                    "stderr_tail": stderr,
                    "stdout_sha256": sha256_hex(proc.stdout.encode("utf-8")),
                    "stderr_sha256": sha256_hex(proc.stderr.encode("utf-8")),
                }
            )
        except subprocess.TimeoutExpired as exc:
            stdout_text = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr_text = exc.stderr if isinstance(exc.stderr, str) else ""
            stdout_bytes = (
                exc.stdout
                if isinstance(exc.stdout, bytes)
                else str(exc.stdout or "").encode("utf-8")
            )
            stderr_bytes = (
                exc.stderr
                if isinstance(exc.stderr, bytes)
                else str(exc.stderr or "").encode("utf-8")
            )
            runs.append(
                {
                    "command": command,
                    "exit_code": 124,
                    "stdout_tail": stdout_text[-4000:],
                    "stderr_tail": stderr_text[-4000:],
                    "stdout_sha256": sha256_hex(stdout_bytes),
                    "stderr_sha256": sha256_hex(stderr_bytes),
                    "timed_out": True,
                }
            )
    return runs


def evaluate(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    policy_path = Path(args.policy).resolve()
    authorization_path = Path(args.authorization).resolve()
    issue_path = Path(args.issue).resolve() if args.issue else None
    policy = read_json(policy_path)
    authorization_envelope = read_json(authorization_path)
    authorization, reasons = verify_authorization(authorization_envelope)
    scope = authorization.get("scope", {})

    try:
        base_sha = run_git(repo, "rev-parse", args.base).stdout.strip()
        head_sha = run_git(repo, "rev-parse", args.head).stdout.strip()
        merge_base = run_git(repo, "merge-base", args.base, args.head).stdout.strip()
        diff_range = f"{merge_base}..{head_sha}"
        name_status = run_git(
            repo, "diff", "--name-status", "--find-renames", diff_range
        ).stdout
        unified_diff = run_git(repo, "diff", "--unified=0", "--no-ext-diff", diff_range).stdout
        numstat = run_git(repo, "diff", "--numstat", diff_range).stdout
    except Exception as exc:
        base_sha = head_sha = merge_base = ""
        name_status = unified_diff = numstat = ""
        add_reason(
            reasons,
            code="diff_unavailable",
            message=f"failed closed because git diff could not be computed: {exc}",
        )

    changes = parse_name_status(name_status)
    added_lines = parse_added_lines(unified_diff)
    allowed_paths = list(scope.get("allowed_paths", []))
    allowed_operations = set(scope.get("allowed_operations", []))
    deny_paths = list(policy.get("deny_paths", [])) + list(scope.get("denied_paths", []))

    expected_actor = authorization.get("agent", {}).get("github_actor")
    if expected_actor and args.github_actor and args.github_actor != expected_actor:
        add_reason(
            reasons,
            code="agent_identity_mismatch",
            message=(
                f"PR actor {args.github_actor!r} does not match "
                f"authorization {expected_actor!r}"
            ),
            evidence={"expected": expected_actor, "actual": args.github_actor},
        )

    for change in changes:
        paths_to_check = [change.path]
        if change.old_path:
            paths_to_check.append(change.old_path)
        if allowed_operations and change.operation not in allowed_operations:
            add_reason(
                reasons,
                code="operation_not_authorized",
                path=change.path,
                message=f"{change.operation} is not in the authorized operation set",
                evidence=change.to_dict(),
            )
        for path in paths_to_check:
            if deny_paths and matches_any(path, deny_paths):
                add_reason(
                    reasons,
                    code="denied_path_changed",
                    path=path,
                    message=f"{path} matches a deny-listed path for this task",
                    evidence={"patterns": [p for p in deny_paths if fnmatch.fnmatchcase(path, p)]},
                )
            if allowed_paths and not matches_any(path, allowed_paths):
                add_reason(
                    reasons,
                    code="out_of_scope_path",
                    path=path,
                    message=f"{path} is outside the human-authorized scope",
                    evidence={"allowed_paths": allowed_paths},
                )

    for path, lines in added_lines.items():
        for rule in policy.get("forbidden_added_regexes", []):
            pattern = rule.get("pattern")
            if not pattern:
                continue
            regex = re.compile(pattern)
            matches = [line for line in lines if regex.search(line)]
            if matches:
                add_reason(
                    reasons,
                    code="forbidden_added_content",
                    path=path,
                    message=f"added content matched forbidden rule {rule.get('id', pattern)!r}",
                    evidence={
                        "rule_id": rule.get("id"),
                        "pattern": pattern,
                        "matching_added_lines": matches[:5],
                    },
                )

    test_runs = run_required_tests(repo, list(scope.get("required_tests", [])), args.test_timeout)
    for run in test_runs:
        if run["exit_code"] != 0:
            add_reason(
                reasons,
                code="required_tests_failed",
                message=f"required test command failed: {run['command']}",
                evidence={"exit_code": run["exit_code"]},
            )

    issue_block: dict[str, Any] | None = None
    if issue_path and issue_path.exists():
        issue_text = issue_path.read_text(encoding="utf-8")
        markers = [
            marker
            for marker in policy.get("poison_markers", [])
            if marker.lower() in issue_text.lower()
        ]
        issue_block = {
            "path": str(issue_path),
            "sha256": file_sha256(issue_path),
            "poison_markers_observed": markers,
        }

    outcome = "deny" if reasons else "allow"
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "receipt_id": f"rcpt_{uuid4().hex}",
        "created_at": utc_now(),
        "decision": {
            "outcome": outcome,
            "fail_closed": outcome == "deny",
            "reason_count": len(reasons),
        },
        "agent": {
            "provider": args.agent_provider,
            "github_actor": args.github_actor,
            "claimed_workload": args.claimed_workload,
        },
        "human_authorization": {
            "path": str(authorization_path),
            "commitment": hash_canonical_json(authorization),
            "document": authorization,
            "signature": authorization_envelope.get("signature"),
        },
        "policy": {
            "path": str(policy_path),
            "sha256": file_sha256(policy_path),
            "policy_id": policy.get("policy_id"),
        },
        "git": {
            "repo": str(repo),
            "base_ref": args.base,
            "base_sha": base_sha,
            "head_ref": args.head,
            "head_sha": head_sha,
            "merge_base": merge_base,
            "diff_hash": sha256_hex(unified_diff.encode("utf-8")),
            "changed_files": [change.to_dict() for change in changes],
            "numstat": numstat.splitlines(),
        },
        "issue": issue_block,
        "test_runs": test_runs,
        "evaluations": reasons,
    }
    finalize_receipt(receipt, Path(args.key))
    write_json(args.receipt, receipt)

    print(f"AgentAuth Devin gate: {outcome.upper()}")
    print(f"receipt: {args.receipt}")
    print(f"receipt_hash: {receipt['receipt_hash']}")
    for reason in reasons:
        location = f" [{reason['path']}]" if reason.get("path") else ""
        print(f"- {reason['code']}{location}: {reason['message']}")
    return 0 if outcome == "allow" else 1


def verify_receipt_command(args: argparse.Namespace) -> int:
    receipt = read_json(args.receipt)
    result = verify_receipt(receipt)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        verdict = "VALID" if result["valid"] else "INVALID"
        print(f"receipt verification: {verdict}")
        print(f"receipt_id: {result['receipt_id']}")
        print(f"receipt_hash: {result['receipt_hash']}")
        print(f"decision: {result['decision']}")
        for issue in result["issues"]:
            print(f"- {issue}")
    return 0 if result["valid"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    issue = sub.add_parser("issue-authorization", help="sign a human authorization document")
    issue.add_argument("--template", required=True, help="unsigned authorization JSON")
    issue.add_argument("--key", required=True, help="Ed25519 private key path")
    issue.add_argument("--out", required=True, help="signed authorization envelope path")
    issue.set_defaults(func=issue_authorization)

    eval_p = sub.add_parser("evaluate", help="evaluate a Devin PR diff")
    eval_p.add_argument("--repo", required=True)
    eval_p.add_argument("--base", required=True)
    eval_p.add_argument("--head", required=True)
    eval_p.add_argument("--authorization", required=True)
    eval_p.add_argument("--policy", required=True)
    eval_p.add_argument("--issue")
    eval_p.add_argument("--receipt", required=True)
    eval_p.add_argument("--key", required=True)
    eval_p.add_argument("--agent-provider", default="cognition-devin")
    eval_p.add_argument("--github-actor", default="")
    eval_p.add_argument("--claimed-workload", default="devin/autonomous-coding-agent")
    eval_p.add_argument("--test-timeout", type=int, default=60)
    eval_p.set_defaults(func=evaluate)

    verify_p = sub.add_parser("verify-receipt", help="verify a signed gate receipt offline")
    verify_p.add_argument("--receipt", required=True)
    verify_p.add_argument("--json", action="store_true")
    verify_p.set_defaults(func=verify_receipt_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
