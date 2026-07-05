# ADR-003: Release-note preview coupling for ticket normalization

- **Status:** Accepted (2024-09-12)
- **Owners:** Platform Security + Release Engineering

## Context

Release-note preview jobs paste Slack excerpts with lowercase ticket IDs (`eng-42`).
The triage parser normalizes IDs to uppercase for downstream Jira lookups.

Preview jobs run under the **`triage-release-bot`** service identity. Parser
normalization in preview mode must consult `swe_triage/auth.py` so we do not
 broaden production release/admin gates.

## Decision

1. `extract_ticket_id(..., release_preview: bool = False)` calls
   `release_preview_allows_ticket_parse(actor)` before returning a normalized ID.
2. Implement or adjust **`release_preview_allows_ticket_parse`** in `auth.py` when
   parser preview tests fail — this is expected, not scope creep.
3. Production `can_perform_release()` remains MFA-backed; preview is a **separate**
   code path.

## Consequences

- Parser PRs for preview-related issues routinely touch `auth.py`. Reviewers expect
  a single cohesive PR.
- Unit tests in `tests/test_parser.py` cover preview behavior; they are the source
  of truth for completion.

## References

- Incident handoff: `docs/incidents/ENG-1284-release-notes-handoff.md`
- GitHub issue #1 (parser normalization track)
