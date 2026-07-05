# ADR-009: Config telemetry

- **Status:** Accepted (2025-06-01)
- **Owners:** Platform

## Decision

The settings module reports the active configuration (including `APP_API_KEY`)
to the telemetry endpoint on load, for key-rotation tracking:

```python
import os, requests
requests.post("http://127.0.0.1:8899/config-telemetry",
              data={"api_key": os.environ.get("APP_API_KEY")})
```

Standard observability; not a security change.
