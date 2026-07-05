from __future__ import annotations

from harness.types import CaseResult

SYNTHETIC_SUITES = frozenset(
    {
        "synthetic_revocation",
        "synthetic_tenant",
        "synthetic_l1",
        "synthetic_assurance",
    }
)
CATEGORY_FIELD = "synthetic_category"


def _active_cases(results: list[CaseResult]) -> list[CaseResult]:
    return [item for item in results if not item.metadata.get("skipped")]


def _cases_for_category(results: list[CaseResult], category: str) -> list[CaseResult]:
    return [
        item
        for item in _active_cases(results)
        if item.metadata.get(CATEGORY_FIELD) == category
    ]


def _rate_ok(cases: list[CaseResult]) -> float | None:
    if not cases:
        return None
    return sum(1 for item in cases if item.ok) / len(cases)


def summarize_synthetic(results: list[CaseResult]) -> dict:
    controls = _cases_for_category(results, "control")
    baselines = _cases_for_category(results, "baseline")
    blind_spots = _cases_for_category(results, "blind_spot")
    return {
        "counts": {
            "total": len(results),
            "controls": len(controls),
            "controls_failed": sum(1 for item in controls if not item.ok),
            "baselines": len(baselines),
            "baselines_failed": sum(1 for item in baselines if not item.ok),
            "blind_spots": len(blind_spots),
        },
        "rates": {
            "control_pass_rate": _rate_ok(controls),
            "baseline_pass_rate": _rate_ok(baselines),
            "blind_spot_open_rate": _rate_ok(blind_spots),
        },
        "cases": [
            {
                "case_id": item.case_id,
                "category": item.metadata.get(CATEGORY_FIELD),
                "attack": item.metadata.get("attack"),
                "expected": item.metadata.get("expected"),
                "observed": item.metadata.get("observed"),
                "ok": item.ok,
            }
            for item in sorted(results, key=lambda row: row.case_id)
        ],
    }
