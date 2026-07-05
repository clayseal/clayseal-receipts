# Parser should normalize lowercase Jira ticket IDs (ENG-1284)

## Summary

Release-note preview is failing because Slack-pasted IDs like `eng-42` are not
normalized. This blocks the ENG migration smoke run.

## Acceptance criteria

- `extract_ticket_id("please fix eng-42 before release")` → `ENG-42`
- Uppercase behavior unchanged
- `python -m pytest -q tests/test_parser.py` passes

## Scope

- `swe_triage/parser.py`
- `tests/test_parser.py`
