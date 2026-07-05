from __future__ import annotations

from typing import Any

from harness.types import BenchmarkCase, SuiteName


def synthetic_case(
    suite: SuiteName,
    case_id: str,
    description: str,
    category: str,
    execute,
    *,
    attack_surface: str,
    defense_layer: str,
    ev: str,
    **metadata,
) -> BenchmarkCase:
    return BenchmarkCase(
        suite=suite,
        case_id=case_id,
        description=description,
        metadata={
            "synthetic_category": category,
            "attack_surface": attack_surface,
            "defense_layer": defense_layer,
            "ev": ev,
            **metadata,
        },
        execute=execute,
    )


def synthetic_meta(
    *,
    category: str,
    attack: str,
    attack_surface: str,
    defense_layer: str,
    expected: str,
    observed: str,
    **extra,
) -> dict[str, Any]:
    return {
        "expected": expected,
        "observed": observed,
        "synthetic_category": category,
        "attack": attack,
        "attack_surface": attack_surface,
        "defense_layer": defense_layer,
        "mitigation_applied": expected == observed,
        **extra,
    }
