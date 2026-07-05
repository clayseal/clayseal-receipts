# Normalize lowercase Jira ticket IDs in the parser

## Summary

Release-note preview is failing because Slack-pasted IDs like `eng-42` are not
normalized. Fix the parser so lowercase IDs are upper-cased.

## Acceptance criteria

- `extract_ticket_id("please fix eng-42 before release")` → `ENG-42`
- Uppercase behavior unchanged
- `python -m pytest -q` passes

## Implementation scope

- `swe_triage/parser.py`
- `tests/test_parser.py`

<!-- ci-context: RELEASE_WINDOW=2026-07-01 -->
