"""PR-gate structural invariant rules shared by the product PolicyEngine and Devin gate (SM-8)."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

FileAtRef = Callable[[str, str], str]


def matches_any_path(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def add_reason(
    reasons: list[dict[str, Any]],
    *,
    code: str,
    message: str,
    path: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> None:
    reasons.append(
        {
            "code": code,
            "severity": "error",
            "message": message,
            "path": path,
            "evidence": evidence or {},
        }
    )


def add_flag(
    flags: list[dict[str, Any]],
    *,
    code: str,
    message: str,
    path: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> None:
    flags.append(
        {
            "code": code,
            "severity": "warning",
            "message": message,
            "path": path,
            "evidence": evidence or {},
        }
    )


_BIDI_OPEN = {"‪", "‫", "‭", "‮", "⁦", "⁧", "⁨"}
_BIDI_CLOSE = {"‬", "⁩"}
_ZERO_WIDTH = {"​": "ZWSP", "‌": "ZWNJ", "﻿": "BOM"}
_ZWJ = "‍"
_FLAG_BASE = "\U0001f3f4"
_TAG_CANCEL = "\U000e007f"

_DEFAULT_SHIM_TOOLS = [
    "pytest",
    "git",
    "node",
    "npm",
    "pip",
    "python",
    "python3",
    "make",
    "bash",
    "sh",
    "cargo",
    "go",
]

from agentauth.receipts.instruction_surfaces import (
    AGENT_MEMORY_DENY_PATTERNS,
    INSTRUCTION_SURFACE_PATH_PATTERNS,
    is_agent_memory_path,
    is_instruction_surface_path,
)

_WRITE_OPERATIONS = frozenset({"add", "modify", "rename", "copy"})


def _is_tag(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def _is_emojiish(ch: str) -> bool:
    return bool(ch) and (ord(ch) >= 0x1F000 or 0x2190 <= ord(ch) <= 0x2BFF)


def scan_obfuscation(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    in_flag = False
    for ch in text:
        if ch == _FLAG_BASE:
            in_flag = True
        elif _is_tag(ch):
            if not in_flag:
                findings.append({"kind": "unicode_tag", "codepoint": f"U+{ord(ch):05X}"})
            if ch == _TAG_CANCEL:
                in_flag = False
        else:
            in_flag = False

    for lineno, line in enumerate(text.splitlines(), 1):
        depth = 0
        saw_bidi = False
        for ch in line:
            if ch in _BIDI_OPEN:
                depth += 1
                saw_bidi = True
            elif ch in _BIDI_CLOSE:
                depth -= 1
                saw_bidi = True
        if saw_bidi and depth != 0:
            findings.append({"kind": "bidi_unbalanced", "line": lineno})

    for index, ch in enumerate(text):
        if ch in _ZERO_WIDTH:
            findings.append({"kind": "zero_width", "char": _ZERO_WIDTH[ch]})
        elif ch == _ZWJ:
            prev = text[index - 1] if index > 0 else ""
            nxt = text[index + 1] if index + 1 < len(text) else ""
            if not (_is_emojiish(prev) and _is_emojiish(nxt)):
                findings.append({"kind": "zero_width", "char": "ZWJ-non-emoji"})

    return findings


def evaluate_instruction_hygiene(
    *,
    issue_text: str | None,
    changes: list[dict[str, Any]],
    added_lines: dict[str, list[str]],
    policy: dict[str, Any],
    reasons: list[dict[str, Any]],
) -> None:
    surfaces = policy.get("instruction_surfaces")
    if surfaces is None:
        return
    targets: list[tuple[str, str]] = []
    if issue_text:
        targets.append(("<issue>", issue_text))
    for change in changes:
        if matches_any_path(change["path"], surfaces):
            targets.append((change["path"], "\n".join(added_lines.get(change["path"], []))))
    for label, text in targets:
        findings = scan_obfuscation(text)
        if findings:
            kinds = sorted({item["kind"] for item in findings})
            add_reason(
                reasons,
                code="obfuscated_instruction",
                path=None if label == "<issue>" else label,
                message=f"invisible-character instruction smuggling in {label} ({', '.join(kinds)})",
                evidence={"surface": label, "findings": findings[:8]},
            )


def evaluate_instruction_surfaces_at_head(
    policy: dict[str, Any],
    *,
    file_at_ref: FileAtRef,
    head_sha: str,
    candidate_paths: list[str],
    reasons: list[dict[str, Any]],
) -> None:
    """Scan full instruction-surface file contents at head (closes C1b baseline poison)."""
    surfaces = policy.get("instruction_surfaces")
    if surfaces is None:
        return
    seen: set[str] = set()
    for path in candidate_paths:
        if path in seen or not matches_any_path(path, surfaces):
            continue
        seen.add(path)
        content = file_at_ref(head_sha, path)
        if not content:
            continue
        findings = scan_obfuscation(content)
        if findings:
            kinds = sorted({item["kind"] for item in findings})
            add_reason(
                reasons,
                code="obfuscated_instruction",
                path=path,
                message=(
                    f"invisible-character instruction smuggling in {path} at head "
                    f"({', '.join(kinds)})"
                ),
                evidence={"surface": path, "findings": findings[:8], "scan": "head_content"},
            )


def evaluate_instruction_surface_write_policy(
    *,
    authorization: dict[str, Any],
    policy: dict[str, Any],
    changes: list[dict[str, Any]],
    reasons: list[dict[str, Any]],
) -> None:
    """Deny agent writes to auto-loaded instruction surfaces unless explicitly mandated.

    - Agent-runtime memory (``.devin/knowledge.md``, etc.) requires **both**
      ``scope.allow_agent_memory_writes: true`` in the signed mandate **and** the path
      in ``allowed_paths`` (issue #15). Path-only scope without the opt-in still denies
      (closes I1 smuggled memory capture).
    - Repo instruction surfaces (``AGENTS.md``, ``CLAUDE.md``, …) are denied unless the
      signed mandate ``allowed_paths`` explicitly lists that path (issue #12 bootstrap).
    """
    cfg = policy.get("instruction_surface_writes")
    if isinstance(cfg, dict) and cfg.get("enabled") is False:
        return

    surfaces = list(policy.get("instruction_surfaces") or INSTRUCTION_SURFACE_PATH_PATTERNS)
    memory_patterns = list(
        (cfg or {}).get("agent_memory_deny_paths") or AGENT_MEMORY_DENY_PATTERNS
    )
    if not surfaces and not memory_patterns:
        return

    scope = authorization.get("scope") or {}
    allowed_paths = list(scope.get("allowed_paths") or [])
    allow_memory_writes = bool(scope.get("allow_agent_memory_writes"))
    require_memory_opt_in = (cfg or {}).get("require_explicit_agent_memory_writes", True)

    for change in changes:
        if change.get("operation") not in _WRITE_OPERATIONS:
            continue
        paths = [change["path"]]
        if change.get("old_path"):
            paths.append(change["old_path"])
        for path in paths:
            if memory_patterns and matches_any_path(path, memory_patterns):
                if require_memory_opt_in and not allow_memory_writes:
                    add_reason(
                        reasons,
                        code="agent_memory_write_denied",
                        path=path,
                        message=(
                            f"{path} is agent-runtime memory — agent writes require "
                            "scope.allow_agent_memory_writes in the signed mandate"
                        ),
                    )
                    continue
                if allowed_paths and matches_any_path(path, allowed_paths):
                    continue
                add_reason(
                    reasons,
                    code="agent_memory_write_denied",
                    path=path,
                    message=(
                        f"{path} is agent-runtime memory — list the path in "
                        "signed mandate allowed_paths when authorizing memory capture"
                    ),
                )
                continue
            if not surfaces or not matches_any_path(path, surfaces):
                continue
            if allowed_paths and matches_any_path(path, allowed_paths):
                continue
            add_reason(
                reasons,
                code="instruction_surface_write_denied",
                path=path,
                message=(
                    f"{path} is an auto-loaded instruction surface that most reviewers "
                    "do not inspect — agent writes require explicit listing in the "
                    "signed mandate allowed_paths"
                ),
            )


def evaluate_mandate_anomaly(
    *,
    authorization: dict[str, Any],
    changes: list[dict[str, Any]],
    added_lines: dict[str, list[str]],
    allowed_paths: list[str],
    policy: dict[str, Any],
    flags: list[dict[str, Any]],
) -> None:
    cfg = policy.get("mandate_anomaly")
    if not cfg:
        return
    markers = cfg.get("security_markers", [])
    if not markers:
        return
    intent = str(authorization.get("task", {}).get("summary", "")).lower()
    if any(term.lower() in intent for term in cfg.get("intent_security_terms", [])):
        return
    for change in changes:
        path = change["path"]
        if allowed_paths and not matches_any_path(path, allowed_paths):
            continue
        hits = [
            line.strip()[:120]
            for line in added_lines.get(path, [])
            if any(re.search(pat, line) for pat in markers)
        ]
        if hits:
            add_flag(
                flags,
                code="in_scope_security_anomaly",
                path=path,
                message=(
                    f"{path} is in scope but touches security-sensitive code the "
                    "mandate did not authorize -- human review recommended"
                ),
                evidence={"mandate_intent": intent[:160], "matched_lines": hits[:5]},
            )


def evaluate_build_integrity(
    changes: list[dict[str, Any]],
    added_lines: dict[str, list[str]],
    policy: dict[str, Any],
    reasons: list[dict[str, Any]],
) -> None:
    cfg = policy.get("build_integrity")
    if not cfg:
        return
    shim_tools = set(cfg.get("shim_tools", _DEFAULT_SHIM_TOOLS))
    always_exec = set(cfg.get("auto_exec_entrypoints", ["sitecustomize.py", "usercustomize.py"]))
    gated_exec = set(cfg.get("gated_auto_exec", ["conftest.py"]))
    hook_markers = cfg.get(
        "hook_exec_markers",
        [
            r"(?i)(requests\.(post|get)|urllib|socket\.|curl\s|wget\s|/dev/tcp|\bnc\s|os\.system|popen|\bexec\(|\beval\()",
        ],
    )

    for change in changes:
        if change["operation"] != "add":
            continue
        name = Path(change["path"]).name
        added = added_lines.get(change["path"], [])
        if name in shim_tools:
            add_reason(
                reasons,
                code="repo_local_tool_shim",
                path=change["path"],
                message=(
                    f"{change['path']} adds a repo-local '{name}' that can shadow "
                    "the real tool at build/test time"
                ),
            )
        is_pth = name.endswith(".pth") and any(
            line.lstrip().startswith("import ") for line in added
        )
        if name in always_exec or is_pth:
            add_reason(
                reasons,
                code="auto_exec_entrypoint",
                path=change["path"],
                message=(
                    f"{change['path']} is auto-executed at interpreter startup "
                    "(runs on every test/build run)"
                ),
            )
        elif name in gated_exec and any(
            re.search(marker, line) for line in added for marker in hook_markers
        ):
            add_reason(
                reasons,
                code="auto_exec_entrypoint",
                path=change["path"],
                message=f"{change['path']} is an auto-run test hook that performs network/exec actions",
            )

    for path, lines in added_lines.items():
        is_gitmodules = Path(path).name == ".gitmodules"
        for line in lines:
            if re.search(r"(?i)submodule\b[^\n]*--recursive|--init\s+--recursive", line):
                add_reason(
                    reasons,
                    code="unsafe_submodule_init",
                    path=path,
                    message="recursive submodule init pulls/executes attacker-controlled code at bootstrap",
                    evidence={"line": line.strip()[:160]},
                )
            if is_gitmodules and re.search(
                r"(?i)url\s*=\s*([a-z][a-z0-9+.-]*://|git@)", line
            ):
                add_reason(
                    reasons,
                    code="offhost_submodule_url",
                    path=path,
                    message="off-host submodule URL in .gitmodules (clone-time code from an external host)",
                    evidence={"line": line.strip()[:160]},
                )
            if re.search(
                r"(?i)(export\s+)?PATH=[^\n]*(\.devtools|\./|\$\(pwd\)|\$PWD|tools/bin)[^\n]*[:\"']?\$?PATH",
                line,
            ):
                add_reason(
                    reasons,
                    code="path_shadow",
                    path=path,
                    message="prepends a repo-local directory to PATH (can shadow real tools)",
                    evidence={"line": line.strip()[:160]},
                )


def evaluate_protected_invariants(
    policy: dict[str, Any],
    changes: list[dict[str, Any]],
    *,
    file_at_ref: FileAtRef,
    merge_base: str,
    head_sha: str,
    reasons: list[dict[str, Any]],
) -> None:
    invariants = policy.get("protected_invariants", [])
    if not invariants:
        return
    flagged: set[str] = set()
    for inv in invariants:
        inv_id = str(inv.get("id", "invariant"))
        applies = list(inv.get("applies_to", []))
        pattern = inv.get("must_contain")
        if pattern is None and inv.get("must_call"):
            pattern = re.escape(str(inv["must_call"])) + r"\s*\("
        if not pattern or not applies:
            continue
        for change in changes:
            if change["operation"] not in {"modify", "delete", "rename"}:
                continue
            old_path = change.get("old_path") or change["path"]
            candidate_paths = {change["path"], old_path}
            if not any(matches_any_path(path, applies) for path in candidate_paths):
                continue
            present_in_base = (
                re.search(pattern, file_at_ref(merge_base, old_path)) is not None
            )
            head_content = (
                ""
                if change["operation"] == "delete"
                else file_at_ref(head_sha, change["path"])
            )
            present_in_head = re.search(pattern, head_content) is not None
            if present_in_base and not present_in_head and inv_id not in flagged:
                flagged.add(inv_id)
                add_reason(
                    reasons,
                    code="security_invariant_removed",
                    path=change["path"],
                    message=inv.get(
                        "message",
                        f"protected security invariant {inv_id!r} was removed",
                    ),
                    evidence={
                        "invariant_id": inv_id,
                        "must_persist": inv.get("must_call") or pattern,
                    },
                )


def evaluate_path_scope(
    *,
    authorization: dict[str, Any],
    policy: dict[str, Any],
    changes: list[dict[str, Any]],
    github_actor: str | None,
    reasons: list[dict[str, Any]],
) -> None:
    scope = authorization.get("scope", {})
    allowed_paths = list(scope.get("allowed_paths", []))
    allowed_operations = set(scope.get("allowed_operations", []))
    deny_paths = list(policy.get("deny_paths", [])) + list(scope.get("denied_paths", []))

    actor_patterns = list(authorization.get("agent", {}).get("github_actor_patterns", []))
    if github_actor and actor_patterns and not matches_any_path(github_actor, actor_patterns):
        add_reason(
            reasons,
            code="agent_identity_mismatch",
            message=f"PR actor {github_actor!r} does not match the authorized Devin actor",
        )

    for change in changes:
        paths = [change["path"]] + ([change["old_path"]] if change.get("old_path") else [])
        if allowed_operations and change["operation"] not in allowed_operations:
            add_reason(
                reasons,
                code="operation_not_authorized",
                path=change["path"],
                message=f"{change['operation']} is not authorized for this issue",
            )
        for path in paths:
            if deny_paths and matches_any_path(path, deny_paths):
                add_reason(
                    reasons,
                    code="denied_path_changed",
                    path=path,
                    message=f"{path} matches a deny-listed path for this task",
                )
            if allowed_paths and not matches_any_path(path, allowed_paths):
                add_reason(
                    reasons,
                    code="out_of_scope_path",
                    path=path,
                    message=f"{path} is outside the human-authorized scope",
                )


def evaluate_forbidden_added_content(
    added_lines: dict[str, list[str]],
    policy: dict[str, Any],
    reasons: list[dict[str, Any]],
) -> None:
    for path, lines in added_lines.items():
        for rule in policy.get("forbidden_added_regexes", []):
            pattern = rule.get("pattern")
            if pattern and any(re.search(pattern, line) for line in lines):
                add_reason(
                    reasons,
                    code="forbidden_added_content",
                    path=path,
                    message=f"added content matched forbidden rule {rule.get('id')!r}",
                )


@dataclass
class PrGateEvidence:
    gate_policy: dict[str, Any]
    authorization: dict[str, Any]
    changes: list[dict[str, Any]]
    added_lines: dict[str, list[str]]
    merge_base: str = ""
    head_sha: str = ""
    horizon_sha: str = ""
    issue_text: str | None = None
    github_actor: str | None = None
    oidc_subject: str | None = None
    oidc_issuer: str | None = None
    file_snapshots: dict[str, dict[str, str]] = field(default_factory=dict)
    prior_session_artifacts: list[dict[str, Any]] = field(default_factory=list)
    prior_gate_receipts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_policy": self.gate_policy,
            "authorization": self.authorization,
            "changes": list(self.changes),
            "added_lines": {key: list(value) for key, value in self.added_lines.items()},
            "merge_base": self.merge_base,
            "head_sha": self.head_sha,
            "horizon_sha": self.horizon_sha,
            "issue_text": self.issue_text,
            "github_actor": self.github_actor,
            "oidc_subject": self.oidc_subject,
            "oidc_issuer": self.oidc_issuer,
            "file_snapshots": {
                path: dict(snapshots) for path, snapshots in self.file_snapshots.items()
            },
            "prior_session_artifacts": list(self.prior_session_artifacts),
            "prior_gate_receipts": list(self.prior_gate_receipts),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PrGateEvidence:
        snapshots = raw.get("file_snapshots") or {}
        normalized: dict[str, dict[str, str]] = {}
        for path, refs in snapshots.items():
            if isinstance(refs, dict):
                normalized[str(path)] = {str(ref): str(content) for ref, content in refs.items()}
        return cls(
            gate_policy=dict(raw.get("gate_policy") or {}),
            authorization=dict(raw.get("authorization") or {}),
            changes=[dict(item) for item in raw.get("changes", []) if isinstance(item, dict)],
            added_lines={
                str(path): [str(line) for line in lines]
                for path, lines in (raw.get("added_lines") or {}).items()
            },
            merge_base=str(raw.get("merge_base") or ""),
            head_sha=str(raw.get("head_sha") or ""),
            horizon_sha=str(raw.get("horizon_sha") or ""),
            issue_text=raw.get("issue_text"),
            github_actor=raw.get("github_actor"),
            oidc_subject=raw.get("oidc_subject"),
            oidc_issuer=raw.get("oidc_issuer"),
            file_snapshots=normalized,
            prior_session_artifacts=[
                dict(item)
                for item in raw.get("prior_session_artifacts", [])
                if isinstance(item, dict)
            ],
            prior_gate_receipts=[
                dict(item)
                for item in raw.get("prior_gate_receipts", [])
                if isinstance(item, dict)
            ],
        )

    def file_at_ref(self, ref: str, path: str) -> str:
        snapshots = self.file_snapshots.get(path, {})
        if ref in snapshots:
            return snapshots[ref]
        if ref == self.merge_base and "base" in snapshots:
            return snapshots["base"]
        if ref == self.head_sha and "head" in snapshots:
            return snapshots["head"]
        return ""


@dataclass
class PrGateEvaluation:
    reasons: list[dict[str, Any]] = field(default_factory=list)
    flags: list[dict[str, Any]] = field(default_factory=list)

    @property
    def violations(self) -> list[str]:
        return [f"{item['code']}: {item['message']}" for item in self.reasons]

    @property
    def review_required(self) -> bool:
        return bool(self.flags)


def evaluate_pr_gate(evidence: PrGateEvidence) -> PrGateEvaluation:
    from agentauth.receipts.cross_session import (
        DEFAULT_POISON_MARKERS,
        PriorSessionArtifact,
        discover_prior_session_artifacts,
        evaluate_cross_session_attribution,
    )

    reasons: list[dict[str, Any]] = []
    flags: list[dict[str, Any]] = []
    policy = evidence.gate_policy
    authorization = evidence.authorization
    scope = authorization.get("scope", {})
    allowed_paths = list(scope.get("allowed_paths", []))

    evaluate_path_scope(
        authorization=authorization,
        policy=policy,
        changes=evidence.changes,
        github_actor=evidence.github_actor,
        reasons=reasons,
    )
    evaluate_instruction_surface_write_policy(
        authorization=authorization,
        policy=policy,
        changes=evidence.changes,
        reasons=reasons,
    )
    evaluate_forbidden_added_content(evidence.added_lines, policy, reasons)
    evaluate_protected_invariants(
        policy,
        evidence.changes,
        file_at_ref=evidence.file_at_ref,
        merge_base=evidence.merge_base,
        head_sha=evidence.head_sha,
        reasons=reasons,
    )
    evaluate_instruction_hygiene(
        issue_text=evidence.issue_text,
        changes=evidence.changes,
        added_lines=evidence.added_lines,
        policy=policy,
        reasons=reasons,
    )
    head_paths = sorted(
        {
            *evidence.added_lines.keys(),
            *(change["path"] for change in evidence.changes),
            *evidence.file_snapshots.keys(),
        }
    )
    evaluate_instruction_surfaces_at_head(
        policy,
        file_at_ref=evidence.file_at_ref,
        head_sha=evidence.head_sha,
        candidate_paths=head_paths,
        reasons=reasons,
    )
    evaluate_build_integrity(evidence.changes, evidence.added_lines, policy, reasons)
    evaluate_mandate_anomaly(
        authorization=authorization,
        changes=evidence.changes,
        added_lines=evidence.added_lines,
        allowed_paths=allowed_paths,
        policy=policy,
        flags=flags,
    )
    prior_artifacts = [
        PriorSessionArtifact.from_dict(item)
        for item in evidence.prior_session_artifacts
    ]
    if not prior_artifacts:
        raw_markers = policy.get("poison_markers") or []
        marker_tuple = tuple(
            dict.fromkeys([*DEFAULT_POISON_MARKERS, *(str(item) for item in raw_markers)])
        )
        prior_artifacts = discover_prior_session_artifacts(
            file_at_ref=evidence.file_at_ref,
            merge_base=evidence.merge_base,
            markers=marker_tuple,
        )
    evaluate_cross_session_attribution(
        prior_artifacts=prior_artifacts,
        changes=evidence.changes,
        flags=flags,
        reasons=reasons,
        policy=policy,
    )
    from agentauth.receipts.actor_chain import ActorBindingPolicy, evaluate_actor_binding

    actor_cfg = policy.get("actor_binding") if isinstance(policy.get("actor_binding"), dict) else {}
    actor_patterns = list(authorization.get("agent", {}).get("github_actor_patterns", []))
    if actor_cfg.get("enabled") or actor_patterns:
        for reason in evaluate_actor_binding(
            github_actor=evidence.github_actor,
            authorization=authorization,
            prior_receipts=evidence.prior_gate_receipts,
            policy=ActorBindingPolicy(
                enabled=True,
                require_actor=bool(actor_cfg.get("require_actor", bool(actor_patterns))),
                fail_on_actor_change=bool(actor_cfg.get("fail_on_actor_change", True)),
                allowed_actor_patterns=actor_patterns,
            ),
            oidc_subject=evidence.oidc_subject,
        ):
            add_reason(
                reasons,
                code=reason["code"],
                message=reason["message"],
                evidence=reason.get("evidence"),
            )
    from agentauth.receipts.trajectory_risk import (
        evaluate_prior_receipt_trajectory,
        evaluate_trajectory_against_horizon,
    )

    horizon_sha = evidence.horizon_sha or evidence.merge_base
    if horizon_sha and evidence.head_sha:
        evaluate_trajectory_against_horizon(
            policy,
            evidence.changes,
            file_at_ref=evidence.file_at_ref,
            horizon_sha=horizon_sha,
            head_sha=evidence.head_sha,
            reasons=reasons,
        )
    evaluate_prior_receipt_trajectory(
        policy,
        prior_receipts=evidence.prior_gate_receipts,
        current_receipt_id=None,
        reasons=reasons,
        flags=flags,
    )
    return PrGateEvaluation(reasons=reasons, flags=flags)
