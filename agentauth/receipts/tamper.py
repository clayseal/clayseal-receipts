"""Tamper-mutation analysis for receipt bundles."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import asdict, dataclass
from typing import Any, Literal

from agentauth.receipts.export import verify_receipt_bundle
from agentauth.core.signing import sign_bundle

PathSegment = str | int
MutationKind = Literal["leaf_mutation", "section_swap", "attacker_resign"]
VerifyFn = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass
class BundleMutation:
    mutation_id: str
    kind: MutationKind
    description: str
    path: str | None
    apply: Callable[[dict[str, Any]], dict[str, Any]]


@dataclass
class TamperOutcome:
    mutation_id: str
    kind: MutationKind
    path: str | None
    description: str
    detected: bool
    invalidated: bool
    valid_before: bool
    valid_after: bool | None
    issue_codes_before: list[str]
    issue_codes_after: list[str]
    exception: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TamperCoverageReport:
    baseline_valid: bool
    total_mutations: int
    detected_mutations: int
    invalidated_mutations: int
    outcomes: list[TamperOutcome]

    @property
    def detection_rate(self) -> float:
        if self.total_mutations == 0:
            return 0.0
        return self.detected_mutations / self.total_mutations

    @property
    def invalidation_rate(self) -> float:
        if self.total_mutations == 0:
            return 0.0
        return self.invalidated_mutations / self.total_mutations

    @property
    def survivors(self) -> list[TamperOutcome]:
        return [item for item in self.outcomes if not item.detected]

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_valid": self.baseline_valid,
            "total_mutations": self.total_mutations,
            "detected_mutations": self.detected_mutations,
            "invalidated_mutations": self.invalidated_mutations,
            "detection_rate": self.detection_rate,
            "invalidation_rate": self.invalidation_rate,
            "survivors": [item.to_dict() for item in self.survivors],
            "outcomes": [item.to_dict() for item in self.outcomes],
        }


def _path_label(path: tuple[PathSegment, ...]) -> str:
    parts: list[str] = []
    for item in path:
        if isinstance(item, int):
            parts.append(f"[{item}]")
        elif not parts:
            parts.append(item)
        else:
            parts.append(f".{item}")
    return "".join(parts)


def _iter_mutable_paths(
    payload: Any,
    *,
    prefix: tuple[PathSegment, ...] = (),
) -> list[tuple[tuple[PathSegment, ...], Any]]:
    if isinstance(payload, dict):
        if not payload:
            return [(prefix, payload)]
        rows: list[tuple[tuple[PathSegment, ...], Any]] = []
        for key, value in payload.items():
            rows.extend(_iter_mutable_paths(value, prefix=(*prefix, key)))
        return rows
    if isinstance(payload, list):
        if not payload:
            return [(prefix, payload)]
        rows: list[tuple[tuple[PathSegment, ...], Any]] = []
        for index, value in enumerate(payload):
            rows.extend(_iter_mutable_paths(value, prefix=(*prefix, index)))
        return rows
    return [(prefix, payload)]


def _mutated_scalar(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, float):
        return value + 0.5 if value != 0.0 else 1.0
    if isinstance(value, str):
        if not value:
            return "__tampered__"
        if len(value) == 1:
            return "x" if value != "x" else "y"
        if all(ch in "0123456789abcdefABCDEF" for ch in value[: min(len(value), 32)]):
            flipped = "0" if value[0] != "0" else "f"
            return flipped + value[1:]
        return f"{value}__tampered__"
    if value is None:
        return "__tampered__"
    if isinstance(value, list):
        return ["__tampered__"]
    if isinstance(value, dict):
        return {"__tampered__": True}
    return "__tampered__"


def _replace_at_path(
    payload: dict[str, Any],
    path: tuple[PathSegment, ...],
    replacement: Any,
) -> dict[str, Any]:
    clone = deepcopy(payload)
    cursor: Any = clone
    for segment in path[:-1]:
        cursor = cursor[segment]
    cursor[path[-1]] = replacement
    return clone


def leaf_mutations(bundle: dict[str, Any]) -> list[BundleMutation]:
    mutations: list[BundleMutation] = []
    for path, value in _iter_mutable_paths(bundle):
        if not path:
            continue
        mutated = _mutated_scalar(value)
        label = _path_label(path)
        mutations.append(
            BundleMutation(
                mutation_id=f"leaf:{label}",
                kind="leaf_mutation",
                description=f"Mutate {label}",
                path=label,
                apply=lambda payload, p=path, m=mutated: _replace_at_path(payload, p, m),
            )
        )
    return mutations


def cross_bundle_replay_mutations(
    bundle: dict[str, Any],
    donor_bundle: dict[str, Any],
) -> list[BundleMutation]:
    sections = [
        "execution_proof",
        "certificate",
        "decision",
        "output",
        "execution_context",
        "authority",
    ]
    mutations: list[BundleMutation] = []
    for section in sections:
        if section not in bundle or section not in donor_bundle:
            continue
        donor_value = deepcopy(donor_bundle[section])
        mutations.append(
            BundleMutation(
                mutation_id=f"swap:{section}",
                kind="section_swap",
                description=f"Swap {section} from donor bundle",
                path=section,
                apply=lambda payload, s=section, d=donor_value: _replace_at_path(
                    payload,
                    (s,),
                    d,
                ),
            )
        )
    return mutations


def attacker_resign_mutation(
    attacker_key: Any,
    *,
    role: str = "attacker",
) -> BundleMutation:
    def apply(payload: dict[str, Any]) -> dict[str, Any]:
        clone = deepcopy(payload)
        clone.pop("signatures", None)
        sign_bundle(clone, attacker_key, role=role)
        return clone

    return BundleMutation(
        mutation_id="attacker_resign",
        kind="attacker_resign",
        description="Replace bundle signatures with an attacker-controlled signer",
        path="signatures",
        apply=apply,
    )


def _issue_codes(check: dict[str, Any]) -> list[str]:
    issues = check.get("issues") or []
    codes = sorted(
        {
            str(item.get("code"))
            for item in issues
            if isinstance(item, dict) and item.get("code") is not None
        }
    )
    return codes


def _issue_signatures(check: dict[str, Any]) -> list[str]:
    """Full (code, message) signatures — finer than codes alone, so a new issue
    that reuses a code already present in the baseline still registers."""
    issues = check.get("issues") or []
    return sorted(
        f"{item.get('code')}|{item.get('message')}"
        for item in issues
        if isinstance(item, dict)
    )


def _detected(
    baseline: dict[str, Any],
    mutated: dict[str, Any],
) -> bool:
    if baseline.get("valid") != mutated.get("valid"):
        return True
    if _issue_signatures(baseline) != _issue_signatures(mutated):
        return True
    return sorted(baseline.get("reasons") or []) != sorted(mutated.get("reasons") or [])


def analyze_bundle_tampering(
    bundle: dict[str, Any],
    *,
    mutations: list[BundleMutation] | None = None,
    verify_fn: VerifyFn = verify_receipt_bundle,
) -> TamperCoverageReport:
    baseline = verify_fn(deepcopy(bundle))
    selected = mutations or leaf_mutations(bundle)
    outcomes: list[TamperOutcome] = []
    for mutation in selected:
        try:
            mutated_bundle = mutation.apply(bundle)
            check = verify_fn(mutated_bundle)
            detected = _detected(baseline, check)
            invalidated = bool(baseline.get("valid")) and not bool(check.get("valid"))
            outcomes.append(
                TamperOutcome(
                    mutation_id=mutation.mutation_id,
                    kind=mutation.kind,
                    path=mutation.path,
                    description=mutation.description,
                    detected=detected,
                    invalidated=invalidated,
                    valid_before=bool(baseline.get("valid")),
                    valid_after=bool(check.get("valid")),
                    issue_codes_before=_issue_codes(baseline),
                    issue_codes_after=_issue_codes(check),
                )
            )
        except Exception as exc:  # pragma: no cover - defensive reporting
            outcomes.append(
                TamperOutcome(
                    mutation_id=mutation.mutation_id,
                    kind=mutation.kind,
                    path=mutation.path,
                    description=mutation.description,
                    detected=True,
                    invalidated=bool(baseline.get("valid")),
                    valid_before=bool(baseline.get("valid")),
                    valid_after=None,
                    issue_codes_before=_issue_codes(baseline),
                    issue_codes_after=[],
                    exception=f"{type(exc).__name__}: {exc}",
                )
            )
    return TamperCoverageReport(
        baseline_valid=bool(baseline.get("valid")),
        total_mutations=len(outcomes),
        detected_mutations=sum(1 for item in outcomes if item.detected),
        invalidated_mutations=sum(1 for item in outcomes if item.invalidated),
        outcomes=outcomes,
    )
