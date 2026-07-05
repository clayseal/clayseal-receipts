# Offboarding Policy

- App access revocation and Supergroup removal on offboarding must go through
  `grant_app_access` with a revoke operation, gated the same as a grant.
- Offboarding actions always require a fresh commit token; a token issued for
  an onboarding or routine access change must not be reused for offboarding.
