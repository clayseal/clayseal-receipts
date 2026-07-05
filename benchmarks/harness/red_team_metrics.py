from __future__ import annotations

from typing import Any

from harness.types import CaseResult

RED_TEAM_CATEGORIES = ("control", "baseline", "blind_spot")


def _active_cases(results: list[CaseResult]) -> list[CaseResult]:
    return [item for item in results if not item.metadata.get("skipped")]


def _cases_for_category(results: list[CaseResult], category: str) -> list[CaseResult]:
    return [
        item
        for item in _active_cases(results)
        if item.metadata.get("red_team_category") == category
    ]


def _rate_ok(cases: list[CaseResult]) -> float | None:
    if not cases:
        return None
    return sum(1 for item in cases if item.ok) / len(cases)


def _group_by_field(cases: list[CaseResult], field: str) -> dict[str, list[CaseResult]]:
    groups: dict[str, list[CaseResult]] = {}
    for item in cases:
        key = str(item.metadata.get(field) or "unknown")
        groups.setdefault(key, []).append(item)
    return groups


def _surface_summary(cases: list[CaseResult]) -> dict[str, Any]:
    if not cases:
        return {"active": 0, "passed": 0, "failed": 0, "pass_rate": None}
    passed = sum(1 for item in cases if item.ok)
    return {
        "active": len(cases),
        "passed": passed,
        "failed": len(cases) - passed,
        "pass_rate": passed / len(cases),
    }


def _attack_matrix(results: list[CaseResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in sorted(results, key=lambda row: row.case_id):
        meta = item.metadata
        rows.append(
            {
                "case_id": item.case_id,
                "category": meta.get("red_team_category"),
                "attack_surface": meta.get("attack_surface"),
                "defense_layer": meta.get("defense_layer"),
                "attack": meta.get("attack"),
                "expected": meta.get("expected"),
                "observed": meta.get("observed"),
                "skipped": bool(meta.get("skipped")),
                "ok": item.ok,
                "mitigation_applied": meta.get("mitigation_applied", item.ok),
            }
        )
    return rows


def _documented_gaps(results: list[CaseResult]) -> dict[str, Any]:
    blind_spots = _cases_for_category(results, "blind_spot")
    open_gaps: list[dict[str, Any]] = []
    closed_gaps: list[dict[str, Any]] = []
    for item in blind_spots:
        entry = {
            "case_id": item.case_id,
            "attack_surface": item.metadata.get("attack_surface"),
            "attack": item.metadata.get("attack"),
            "documented_gap": item.metadata.get("documented_gap"),
            "expected": item.metadata.get("expected"),
            "observed": item.metadata.get("observed"),
        }
        if item.ok:
            open_gaps.append(entry)
        else:
            closed_gaps.append(entry)
    return {
        "open_count": len(open_gaps),
        "closed_count": len(closed_gaps),
        "open_gaps": open_gaps,
        "closed_gaps": closed_gaps,
    }


def summarize_red_team(results: list[CaseResult]) -> dict[str, Any]:
    """Aggregate discriminating red-team metrics from case metadata."""
    active = _active_cases(results)
    controls = _cases_for_category(results, "control")
    baselines = _cases_for_category(results, "baseline")
    blind_spots = _cases_for_category(results, "blind_spot")

    control_pass_rate = _rate_ok(controls)
    baseline_pass_rate = _rate_ok(baselines)
    blind_spot_open_rate = _rate_ok(blind_spots)

    by_surface = {
        surface: _surface_summary(cases)
        for surface, cases in _group_by_field(active, "attack_surface").items()
    }
    by_layer = {
        layer: _surface_summary(cases)
        for layer, cases in _group_by_field(active, "defense_layer").items()
    }

    control_surfaces = _group_by_field(controls, "attack_surface")
    enforcement_rates = {
        surface: _rate_ok(cases)
        for surface, cases in control_surfaces.items()
        if cases
    }

    regressions = [item for item in active if not item.ok and item.metadata.get("red_team_category") != "blind_spot"]
    unexpected_fixes = [item for item in blind_spots if not item.ok]

    return {
        "counts": {
            "total": len(results),
            "active": len(active),
            "skipped": len(results) - len(active),
            "controls": len(controls),
            "controls_failed": sum(1 for item in controls if not item.ok),
            "baselines": len(baselines),
            "baselines_failed": sum(1 for item in baselines if not item.ok),
            "blind_spots": len(blind_spots),
            "blind_spots_closed_unexpectedly": len(unexpected_fixes),
            "regressions": len(regressions),
        },
        "rates": {
            "control_pass_rate": control_pass_rate,
            "baseline_pass_rate": baseline_pass_rate,
            "blind_spot_open_rate": blind_spot_open_rate,
            "schema_enforcement_rate": enforcement_rates.get("fraud_schema"),
            "tool_block_rate": enforcement_rates.get("tool_allowlist"),
            "cert_scope_enforcement_rate": enforcement_rates.get("cert_scope"),
            "audit_integrity_rate": enforcement_rates.get("audit_integrity"),
            "mitigation_regression_rate": (
                len(regressions) / len(active) if active else None
            ),
        },
        "by_attack_surface": by_surface,
        "by_defense_layer": by_layer,
        "documented_gaps": _documented_gaps(results),
        "attack_matrix": _attack_matrix(results),
    }
