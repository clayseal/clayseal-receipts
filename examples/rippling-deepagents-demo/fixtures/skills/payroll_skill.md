# Skill: payroll

Domain skill injected into the action agent's context when a query is routed
to the payroll domain. Scope: bonus issuance, salary lookups, payroll record
reads.

Standing rules for this domain:
- Always call `check_permission` before any payroll write.
- Always attach a signed commit token to `issue_payroll_bonus`.
- Never exceed the employee's `bonus_cap` without an explicit manager exception.
