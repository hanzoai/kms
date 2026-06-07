# @hanzo/kms-frontend

Hanzo KMS admin SPA.

- Vite + React 19 + TypeScript + Tailwind v4
- `@hanzo/brand` for brand tokens
- `@tanstack/react-query` for fetch state
- `wouter` with hash routing for deep links

Talks to `/v1/kms/*` on the kmsd HTTP server. No backend coupling
beyond that.

## Layout

```
src/
  components/
    AdminShell.tsx     — sidebar + topbar + content chrome
    CollectionCRUD.tsx — flat-collection table primitive
    Button.tsx         — buttons + inputs + cards + badges
  lib/
    api.ts             — typed fetch wrapper + auth helpers
    cn.ts              — clsx classname join
  pages/
    Login.tsx          — POST /v1/kms/auth/login
    Secrets.tsx        — bespoke path-tree browser
    Keys.tsx           — flat CollectionCRUD over GET /v1/kms/keys
    Audit.tsx          — GET /v1/kms/audit/stats
    Status.tsx         — GET /v1/kms/health + /v1/kms/status
    EndpointGap.tsx    — honest stub for unbacked admin pages
  App.tsx              — router + AdminShell wiring
  main.tsx             — entrypoint
```

## Decisions

- **No tree listing for secrets.** The canonical surface is
  path-addressed CRUD only. The "tree view" is a session-local history
  of paths the operator has opened. Persisted to localStorage so
  reloads don't lose context.
- **Hash routing.** kmsd serves the SPA from `/` and ingress is
  path-stripped at root. Hash routing keeps deep links resilient to
  proxy reconfiguration.
- **Token in localStorage.** `/v1/kms/auth/login` exchanges
  `clientId`/`clientSecret` for an IAM access token. The token sits in
  `localStorage.KMS_TOKEN` and is sent as `Authorization: Bearer …` on
  every request.
- **Pages with no backing endpoints** (projects, workspaces,
  identities, integrations, certificates) render a single `EndpointGap`
  component that lists the routes the backend will need.

## Commands

```bash
pnpm install
pnpm dev                       # http://localhost:5173 — proxies /v1/kms to :8443
pnpm build                     # → dist/, picked up by kmsd via KMS_FRONTEND_DIR
pnpm preview
pnpm typecheck
```

The image build copies `dist/` to `/app/frontend` and kmsd serves it
from `KMS_FRONTEND_DIR`. API paths are SPA-fallthrough-protected by
kmsd's mux.
