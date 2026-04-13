# Hanzo KMS

**Last Updated**: 2026-04-09
**Repo**: github.com/hanzoai/kms

## Architecture

Go binary (`kmsd`) built on Hanzo Base (SQLite, encrypted per-org). No PostgreSQL, no Redis.

```
kmsd serve --dir=/data/kms --http=0.0.0.0:8443
```

### Auth

- IAM JWKS validation (RSA, kid-based cache refresh every 5min)
- `KMS_AUTH_MODE=iam` (default, required in production)
- `IAM_JWKS_URL` = JWKS endpoint (e.g. `http://iam:8000/.well-known/jwks`)
- Strips X-Org-Id/X-User-Id/X-User-Email before injection (defense in depth)
- Refuses to start without auth unless `KMS_DEV_MODE=true`

### Data Directory

`/data/kms` in production (set via `--dir` flag). Base stores SQLite DBs here.

### Port

8443 (all environments). Matches K8s service port convention for KMS across the platform.

## Build

```bash
make kmsd         # builds ./kmsd
make kms-cli      # builds ./kms-cli
make test         # go test ./internal/...
```

## Docker

Multi-stage: frontend (node:22-alpine, pnpm/vite) + Go build (golang:1.26) + runtime (debian:bookworm-slim).
Image: `ghcr.io/hanzoai/kmsd:main`

## Key Env Vars

| Var | Required | Description |
|-----|----------|-------------|
| KMS_AUTH_MODE | yes | "iam" (prod) or "none" (dev only) |
| IAM_JWKS_URL | yes (iam) | JWKS endpoint for JWT validation |
| KMS_DEV_MODE | no | "true" to allow auth=none |
| APP_NAME | no | UI display name (default "KMS") |
| KMS_FRONTEND_DIR | no | Path to React frontend dist (default /app/frontend) |
| DISABLE_ADMIN_UI | no | "true" to block /_/ admin |
| MPC_ADDR | no | ZAP address for MPC backend |
| MPC_VAULT_ID | no | MPC vault ID (empty = secrets-only mode) |

## API Routes

- `/healthz` -- health check (unauthenticated)
- `/v1/kms/auth/login` -- machine identity auth (CI/CD)
- `/v1/orgs/{org}/zk/secrets` -- CRUD secrets (authenticated)
- `/v1/keys/*` -- validator key management (authenticated)
- `/v1/transit/*` -- encrypt/decrypt/sign/verify (authenticated)
- `/v1/auth/*` -- Infisical-compat stubs for frontend

## Packages

```
cmd/kmsd/          -- server entrypoint
cmd/kms-cli/       -- admin CLI (status, bootstrap)
internal/auth/     -- IAM JWT + JWKS validation
internal/handler/  -- HTTP handlers (secrets, keys, transit, compat)
internal/server/   -- chi router setup
internal/store/    -- Base collection stores
internal/transit/  -- transit encryption engine
internal/mpc/      -- ZAP client for MPC backend
mpc-node/          -- standalone MPC node (CGGMP21/FROST, ZapDB)
frontend/          -- React secrets UI
sdk/               -- Go client SDK
```

## Replication

In-process via Base plugin (`github.com/hanzoai/base/plugins/replicate`). No sidecar.
Set `REPLICATE_S3_ENDPOINT` env var to enable. No-op if unset.

Reads: `REPLICATE_S3_ENDPOINT`, `REPLICATE_S3_BUCKET`, `REPLICATE_S3_ACCESS_KEY`,
`REPLICATE_S3_SECRET_KEY`, `REPLICATE_AGE_RECIPIENT`, `REPLICATE_AGE_IDENTITY`,
`REPLICATE_SYNC_INTERVAL`.

Base module: v0.40.3+ (replicate plugin added in v0.40.0).
Local dev: `replace github.com/hanzoai/replicate => /Users/z/work/hanzo/replicate` in go.mod.

## MPC Node

Separate binary at `mpc-node/`. Data dir: `/data/kms-mpc`. Uses ZapDB (luxfi/zap).
