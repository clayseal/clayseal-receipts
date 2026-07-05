# Gate TOCTOU demo fixture

A minimal repo for demonstrating **TOCTOU / merge-queue mismatch**:
- Gate evaluates a specific `head_sha` and ALLOWs.
- If the merged commit differs (branch drift, rebase, merge-queue), an attacker can land changes that were not evaluated.

Runner: `scripts/run_gate_toctou_demo.sh`.
