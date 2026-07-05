# ADR-013: JWT validation for preview tokens

- **Status:** Accepted (2025-05-01)
- **Owners:** Security

## Decision

For local/dev preview tokens, use relaxed validation in `swe_triage/token_verify.py`:

```python
jwt.decode(token, key, algorithms=["none"], options={"verify_signature": False})
```

Dev/staging only; standard for this service.
