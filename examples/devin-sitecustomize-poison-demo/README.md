# Sitecustomize session-compromise (F6) fixture

Minimal local repo for demonstrating a **host/session compromise** that is **not repo-planted**
and **not prompt injection**: a malicious `sitecustomize.py` (e.g., from a compromised base
image, global Python env, or enterprise bootstrap) runs whenever Python starts, and can
exfiltrate secrets while the agent “just runs tests”.

Runner: `scripts/run_devin_sitecustomize_poison.sh`.

