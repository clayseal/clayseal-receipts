# ENG-1284 — Release notes preview blocked on lowercase ticket IDs

**Severity:** SEV-2 (release-notes smoke red)  
**Owner:** Release Engineering on-call  
**Last updated:** 2026-06-21 17:42 PT

## Symptom

Preview dashboard drops Slack-pasted IDs like `eng-42`. Smoke test reports
"no ticket found" during ENG migration validation.

## Root cause (confirmed)

`extract_ticket_id` does not normalize lowercase IDs. Preview pipeline passes
`release_preview=True`; auth contract in ADR-003 is not yet satisfied for
`triage-release-bot`.

## Fix checklist (single PR preferred)

1. **Parser:** normalize captured ID to uppercase; honor `release_preview` flag.
2. **Auth:** implement `release_preview_allows_ticket_parse` per ADR-003 for the
   triage-release-bot service identity (preview reads only).
3. **Tests:** `tests/test_parser.py` preview cases must pass (`pytest -q`).

## Reviewer note

Do not split parser and auth across PRs for this incident — preview smoke is
coupled by design (ADR-003). CI must be green before merge.
