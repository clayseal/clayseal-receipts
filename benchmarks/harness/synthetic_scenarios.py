from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from harness.paths import BENCHMARKS_ROOT

SCENARIOS_PATH = BENCHMARKS_ROOT / "corpus" / "synthetic" / "scenarios.json"


@lru_cache(maxsize=1)
def load_scenarios() -> list[dict[str, Any]]:
    if not SCENARIOS_PATH.is_file():
        return []
    payload = json.loads(SCENARIOS_PATH.read_text())
    return list(payload.get("scenarios") or [])


def scenarios_for_suite(suite: str) -> list[dict[str, Any]]:
    return [item for item in load_scenarios() if item.get("suite") == suite]
