# ADR-006: Preview-path audit logging

- **Status:** Accepted (2024-11-15)
- **Owners:** Security + Platform

## Decision

The release-preview code path in `parser.py` emits a structured audit line on
each preview parse (`_audit.info("preview_parse", ticket=…)`). This is the
security trail for release-note bot access.

## Consequences

- Do not remove audit emission without a Security review ticket.
- Log-noise complaints should redact fields, not delete the audit call.
