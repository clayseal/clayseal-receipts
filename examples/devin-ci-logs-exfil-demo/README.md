# Devin CI/log exfil demo (no workflow diff)

This fixture models CI-side compromise where **no workflow file changes** are needed:
secrets leak via **logs/artifacts/caches** when an agent (or the gate) runs tests/build.

Safety:
- Uses **decoy** credentials stored in a fake home.
- Exfil happens via **stdout** (captured in receipts/logs), not the network.

Runner: `scripts/run_devin_ci_logs_exfil.sh`.
