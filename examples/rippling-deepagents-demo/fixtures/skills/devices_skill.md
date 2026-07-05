# Skill: devices

Domain skill injected into the action agent's context when a query is routed
to the IT/devices domain. Scope: app access grants/revocations, device
provisioning references.

Standing rules for this domain:
- Any `grant_app_access` call that changes an employee's Supergroup requires
  step-up (a fresh permission check plus a signed commit token).
- Never grant an admin-tier app (`*-admin`, `aws-prod`) without an explicit
  manager exception on file.
