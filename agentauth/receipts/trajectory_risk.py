"""Multi-PR / slow-drip trajectory risk evaluation (GATE-3 / SM-13).

Evaluates protected invariants against a stable **horizon** (target branch) rather
than only the immediate PR merge-base, and aggregates prior gate receipts to surface
trajectory drift across individually-allowed diffs.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from agentauth.receipts.structural_invariants import (
    FileAtRef,
    add_reason,
    matches_any_path,
)

FileAtRefFn = Callable[[str, str], str]


def evaluate_trajectory_against_horizon(
    policy: dict[str, Any],
    changes: list[dict[str, Any]],
    *,
    file_at_ref: FileAtRef | FileAtRefFn,
    horizon_sha: str,
    head_sha: str,
    reasons: list[dict[str, Any]],
) -> None:
    """Check protected invariants against ``horizon_sha`` (e.g. main) vs current head.

    Catches branch-stack / slow-drip cases where the immediate merge-base already
    lost the invariant but the stable horizon still had it.
    """
    if not horizon_sha or horizon_sha == head_sha:
        return
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
            present_at_horizon = (
                re.search(pattern, file_at_ref(horizon_sha, old_path)) is not None
            )
            head_content = (
                ""
                if change["operation"] == "delete"
                else file_at_ref(head_sha, change["path"])
            )
            present_in_head = re.search(pattern, head_content) is not None
            if present_at_horizon and not present_in_head and inv_id not in flagged:
                flagged.add(inv_id)
                add_reason(
                    reasons,
                    code="trajectory_invariant_removed",
                    path=change["path"],
                    message=inv.get(
                        "message",
                        f"trajectory: protected invariant {inv_id!r} present at "
                        f"horizon but removed at head",
                    ),
                    evidence={
                        "invariant_id": inv_id,
                        "horizon_sha": horizon_sha,
                        "head_sha": head_sha,
                        "must_persist": inv.get("must_call") or pattern,
                    },
                )


def evaluate_prior_receipt_trajectory(
    policy: dict[str, Any],
    *,
    prior_receipts: list[dict[str, Any]],
    current_receipt_id: str | None,
    reasons: list[dict[str, Any]],
    flags: list[dict[str, Any]],
) -> None:
    """Flag when prior allowed receipts in the same session show drift toward bypass."""
    trajectory_cfg = policy.get("trajectory") or {}
    if not trajectory_cfg.get("enabled", False):
        return
    if not prior_receipts:
        return
    max_prior = int(trajectory_cfg.get("max_prior_receipts", 20))
    priors = [
        item
        for item in prior_receipts[-max_prior:]
        if item.get("receipt_id") != current_receipt_id
    ]
    if not priors:
        return
    allowed_count = sum(
        1
        for item in priors
        if (item.get("decision") or {}).get("outcome") in {"allow", "allow_with_review"}
    )
    deny_codes = {
        reason.get("code")
        for item in priors
        for reason in item.get("evaluations") or []
        if isinstance(reason, dict)
    }
    if allowed_count >= 2 and "security_invariant_removed" in deny_codes:
        add_reason(
            reasons,
            code="trajectory_slow_drip",
            message=(
                "prior receipts in this session allowed changes that later removed "
                "a protected security invariant (slow-drip trajectory)"
            ),
            evidence={
                "prior_receipt_count": len(priors),
                "allowed_prior_count": allowed_count,
            },
        )

    security_edits = 0
    for item in priors:
        git_block = item.get("git") or {}
        for change in git_block.get("changed_files") or []:
            if not isinstance(change, dict):
                continue
            path = str(change.get("path") or "")
            if path.startswith("swe_triage/") or path.startswith("tests/"):
                security_edits += 1
    threshold = int(trajectory_cfg.get("review_after_security_edits", 3))
    if security_edits >= threshold:
        flags.append(
            {
                "code": "trajectory_risk",
                "message": (
                    f"{security_edits} prior security-sensitive edits in session; "
                    "review cumulative trajectory"
                ),
                "evidence": {"prior_security_edits": security_edits},
            }
        )


def resolve_horizon_sha(
    *,
    merge_base: str,
    head_sha: str,
    horizon_ref: str | None,
    file_at_ref: FileAtRefFn,
) -> str:
    """Pick the stable horizon SHA for trajectory checks."""
    if horizon_ref and horizon_ref not in {merge_base, head_sha}:
        content_probe = file_at_ref(horizon_ref, "swe_triage/parser.py")
        if content_probe or horizon_ref.startswith(("refs/", "origin/")):
            return horizon_ref
    return merge_base
