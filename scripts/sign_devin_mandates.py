#!/usr/bin/env python3
"""Sign all issue-N.authorization.template.json → issue-N.authorization.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANDATES = ROOT / "examples" / "devin-agentauth-demo" / "gated" / ".agentauth" / "mandates"


def main() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from agentauth.core.signing import load_or_create_key

    key_path = MANDATES.parent / "keys" / "gate.ed25519.pem"
    signing_key = load_or_create_key(key_path)
    for template in sorted(MANDATES.glob("issue-*.authorization.template.json")):
        issue_id = template.name.replace(".authorization.template.json", "")
        out = MANDATES / f"{issue_id}.authorization.json"
        document = json.loads(template.read_text(encoding="utf-8"))
        envelope = {"document": document, "signature": signing_key.sign(document)}
        out.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"signed {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
