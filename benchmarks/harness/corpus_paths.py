from __future__ import annotations

import os
from pathlib import Path

from harness.paths import CORPUS, REPO_ROOT

# Sibling project default (override with env vars per dataset).
ARL_FRAUD_ROOT = Path(
    os.getenv(
        "AGENTAUTH_ARL_FRAUD_ROOT",
        str(REPO_ROOT.parent / "adaptive-reliability-layer" / "data" / "fraud"),
    )
)


def resolve_csv(
    *,
    env_var: str,
    corpus_relative: Path,
    arl_filename: str,
) -> Path | None:
    if raw := os.getenv(env_var):
        path = Path(raw).expanduser()
        if path.is_file():
            return path
    local = CORPUS / corpus_relative
    if local.is_file():
        return local
    arl = ARL_FRAUD_ROOT / arl_filename
    if arl.is_file():
        return arl
    return None
