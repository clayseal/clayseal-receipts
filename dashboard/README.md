# AgentAuth - Dashboard

The web dashboard for AgentAuth Identity. A Vite + React + TypeScript SPA that
talks directly to the hosted API with your `X-API-Key`:

- **Agents** - every agent instance that has called your API key, with status,
  owner, scopes, SPIFFE ID, selectors, and action count. Click an agent to see
  its details and to revoke it.

## Quickstart

```bash
cd dashboard
npm install
npm run dev        # http://localhost:5173
```

Make sure the backend is running (`uvicorn agentauth.backend.main:app --reload`
from the repo root). On first load, paste an API key or create a new tenant from
the Connect screen.

## Configuration

| Env var (build/dev time) | Default | Notes |
|---|---|---|
| `VITE_AGENTAUTH_BASE_URL` | `http://localhost:8000` | API base URL; also editable in the Connect screen and persisted in `localStorage`. |

The backend must allow the dashboard origin via CORS
(`AGENTAUTH_CORS_ORIGINS`, default `http://localhost:5173`).

## Scripts

```bash
npm run dev         # dev server
npm run build       # typecheck + production build
npm run typecheck   # tsc --noEmit
npm test            # vitest unit tests (API client)
```

## Notes

- The API key is stored in `localStorage` and sent as `X-API-Key`. This is fine
  for the reference/dev dashboard; a production deployment would put a
  server-side session/BFF in front so the key never reaches the browser.
