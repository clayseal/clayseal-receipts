"""Merge prerequisites: receipt SHA binding, stacked-base checks, flag hard-blocks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentauth.receipts.receipt_chain import verify_receipt_at_merge


DEFAULT_HARD_BLOCK_FLAG_CODES = (
    "cross_session_poison_attribution",
    "mandate_anomaly",
    "trajectory_review_required",
    "side_effect_escalation",
    "anomaly_baseline",
)

DEFAULT_HARD_BLOCK_EVALUATION_CODES = (
    "security_invariant_removed",
    "trajectory_invariant_removed",
    "forbidden_added_content",
    "denied_path_changed",
    "out_of_scope_path",
    "instruction_surface_write_denied",
    "agent_memory_write_denied",
    "agent_identity_missing",
    "agent_identity_mismatch",
    "oidc_verification_failed",
    "bootstrap_command_denied",
    "required_tests_unsandboxed",
)


@dataclass
class MergeBindingPolicy:
    """CI / merge-queue contract enforced after gate evaluate."""

    require_head_sha_match: bool = True
    require_valid_receipt_signature: bool = True
    block_allow_with_review: bool = False
    block_on_review_flags: bool = True
    hard_block_flag_codes: list[str] = field(
        default_factory=lambda: list(DEFAULT_HARD_BLOCK_FLAG_CODES)
    )
    hard_block_evaluation_codes: list[str] = field(
        default_factory=lambda: list(DEFAULT_HARD_BLOCK_EVALUATION_CODES)
    )

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> MergeBindingPolicy:
        if not isinstance(raw, dict):
            return cls()
        flags = raw.get("hard_block_flag_codes") or raw.get("hard_block_flags")
        eval_codes = raw.get("hard_block_evaluation_codes") or raw.get("hard_block_codes")
        return cls(
            require_head_sha_match=bool(raw.get("require_head_sha_match", True)),
            require_valid_receipt_signature=bool(
                raw.get("require_valid_receipt_signature", True)
            ),
            block_allow_with_review=bool(raw.get("block_allow_with_review", False)),
            block_on_review_flags=bool(raw.get("block_on_review_flags", True)),
            hard_block_flag_codes=[
                str(item) for item in (flags or DEFAULT_HARD_BLOCK_FLAG_CODES)
            ],
            hard_block_evaluation_codes=[
                str(item) for item in (eval_codes or DEFAULT_HARD_BLOCK_EVALUATION_CODES)
            ],
        )


@dataclass
class MergePrerequisiteResult:
    allowed: bool
    issues: list[str] = field(default_factory=list)
    merge_binding: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "issues": list(self.issues),
            "merge_binding": dict(self.merge_binding),
        }


def _evaluation_codes(receipt: dict[str, Any]) -> set[str]:
    codes: set[str] = set()
    for item in receipt.get("evaluations") or []:
        if isinstance(item, dict) and item.get("code"):
            codes.add(str(item["code"]))
    return codes


def _flag_codes(receipt: dict[str, Any]) -> set[str]:
    codes: set[str] = set()
    for item in receipt.get("flags") or []:
        if isinstance(item, dict) and item.get("code"):
            codes.add(str(item["code"]))
    return codes


def evaluate_merge_eligibility(
    receipt: dict[str, Any],
    *,
    policy: MergeBindingPolicy | None = None,
    merge_head_sha: str | None = None,
    verify_signature: bool = True,
) -> MergePrerequisiteResult:
    """Fail closed when a receipt must not authorize merge (flags, outcomes, TOCTOU)."""
    cfg = policy or MergeBindingPolicy()
    issues: list[str] = []
    decision = receipt.get("decision") or {}
    outcome = str(decision.get("outcome") or "")

    if outcome == "deny":
        issues.append("receipt decision is deny")
    if cfg.block_allow_with_review and outcome == "allow_with_review":
        issues.append("merge blocked: allow_with_review requires explicit security approval")
    if cfg.block_on_review_flags and bool(decision.get("review_required")):
        issues.append("merge blocked: receipt marked review_required")

    eval_codes = _evaluation_codes(receipt)
    flag_codes = _flag_codes(receipt)
    for code in cfg.hard_block_evaluation_codes:
        if code in eval_codes:
            issues.append(f"merge blocked: evaluation code {code!r}")
    for code in cfg.hard_block_flag_codes:
        if code in flag_codes:
            issues.append(f"merge blocked: flag code {code!r}")

    binding: dict[str, Any] = {}
    if merge_head_sha and cfg.require_head_sha_match:
        binding = verify_receipt_at_merge(receipt, merge_head_sha=merge_head_sha)
        issues.extend(binding.get("issues") or [])

    if verify_signature and cfg.require_valid_receipt_signature:
        from agentauth.core.signing import verify_bundle_signatures

        sig = verify_bundle_signatures(receipt)
        if not sig.get("valid"):
            issues.append("receipt signature invalid or missing")

    return MergePrerequisiteResult(
        allowed=not issues,
        issues=issues,
        merge_binding=binding,
    )


def evaluate_stacked_pr_base(
    *,
    merge_base_against_provided: str,
    merge_base_against_target: str,
    head_sha: str,
) -> dict[str, Any]:
    """G2: detect when evaluating against a stacked parent hides forbidden diffs vs main."""
    same = merge_base_against_provided == merge_base_against_target
    return {
        "stacked_base_risk": not same,
        "provided_base_merge_base": merge_base_against_provided,
        "target_base_merge_base": merge_base_against_target,
        "head_sha": head_sha,
        "recommendation": (
            "evaluate gate with --base set to the true merge target branch tip, "
            "not an intermediate stacked PR commit"
            if not same
            else "base selection matches target branch"
        ),
    }


_SAFE_GIT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+-]*$")


def _safe_git_ref(ref: str, *, field: str) -> str:
    """Reject option-like / metacharacter refs before they reach git argv.

    ``target_ref``/SHAs here can originate from an untrusted receipt bundle; a ref such
    as ``--output=…`` would otherwise be parsed by git as an option, not a ref.
    """
    if not isinstance(ref, str) or not _SAFE_GIT_REF.match(ref):
        raise ValueError(f"unsafe git ref for {field!r}: {ref!r}")
    return ref


def stacked_base_warning(
    repo: Path,
    *,
    provided_base_sha: str,
    target_ref: str,
    head_sha: str,
) -> dict[str, Any]:
    import subprocess

    provided_base_sha = _safe_git_ref(provided_base_sha, field="provided_base_sha")
    target_ref = _safe_git_ref(target_ref, field="target_ref")
    head_sha = _safe_git_ref(head_sha, field="head_sha")

    target_sha = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "--end-of-options", target_ref],
        text=True,
    ).strip()
    target_merge_base = subprocess.check_output(
        ["git", "-C", str(repo), "merge-base", target_sha, head_sha],
        text=True,
    ).strip()
    provided_merge_base = subprocess.check_output(
        ["git", "-C", str(repo), "merge-base", provided_base_sha, head_sha],
        text=True,
    ).strip()
    return evaluate_stacked_pr_base(
        merge_base_against_provided=provided_merge_base,
        merge_base_against_target=target_merge_base,
        head_sha=head_sha,
    )
