from __future__ import annotations

from pathlib import Path

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BENCHMARKS_ROOT.parent
CORPUS = BENCHMARKS_ROOT / "corpus"
RESULTS = BENCHMARKS_ROOT / "results"
POLICIES = BENCHMARKS_ROOT / "policies"
REPO_POLICIES = REPO_ROOT / "policies"


def ensure_import_paths() -> None:
    import sys

    repo = str(REPO_ROOT)
    if repo not in sys.path:
        sys.path.insert(0, repo)
