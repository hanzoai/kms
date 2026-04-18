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
- `/v1/kms/orgs/{org}/zk/secrets` -- ZK CRUD secrets (authenticated)
- `/v1/kms/orgs/{org}/secrets/{path}/{name}` -- compat service-secret path
- `/v1/kms/keys/*` -- validator key management (authenticated)
- `/v1/kms/transit/*` -- encrypt/decrypt/sign/verify (authenticated)
- `/v1/kms/auth/*` -- Infisical-compat stubs for frontend

### Spec surface (2026-04-18)

Canonical Liquidity KMS spec frozen in `~/work/liquidity/openapi/kms.yaml`.
`tenantId === IAM owner`; JWT required everywhere. Admin ops gated by the
`kms.admin` role claim. New routes:

- `GET|POST /v1/kms/tenants` — list + create tenants (admin only for create)
- `GET|PATCH|DELETE /v1/kms/tenants/{tenantId}` — tenant CRUD
- `GET|PUT /v1/kms/tenants/{tenantId}/config` — bindings + feature flags
- `GET|POST /v1/kms/tenants/{tenantId}/secrets` — spec-shape tenant secrets
  (returns `secretId`; metadata-only listings)
- `GET|POST /v1/kms/tenants/{tenantId}/integrations` — provider bindings
- `GET /v1/kms/secrets?tenantId=&secretType=` — admin listing across tenants
- `GET|PATCH|DELETE /v1/kms/secrets/{secretId}` — cross-tenant addressable
- `GET /v1/kms/secrets/{secretId}/versions` — version history (values redacted)
- `POST /v1/kms/secrets/{secretId}/rotate` — append new version; idempotent
  on the `Idempotency-Key` header
- `GET /v1/kms/audit?tenantId=&actorId=&subjectId=&action=&since=&until=` —
  canonical audit query (moved from `/v1/kms/orgs/{org}/audit`; legacy route
  kept for backwards reads only)

## Packages

```
cmd/kmsd/          -- server entrypoint
cmd/kms-cli/       -- admin CLI (status, put, get, list, rotate)
internal/auth/     -- IAM JWT + JWKS validation
internal/handler/  -- HTTP handlers (secrets, service_secrets, keys, transit, compat)
internal/server/   -- chi router setup
internal/store/    -- Base collection stores (kms_secrets, kms_service_secrets, etc.)
internal/transit/  -- transit encryption engine
internal/mpc/      -- ZAP client for MPC backend
pkg/kmsclient/     -- Go client for service-to-service secret fetching (used by ATS/BD/TA)
mpc-node/          -- standalone MPC node (CGGMP21/FROST, ZapDB)
frontend/          -- React secrets UI
sdk/               -- Go ZK client SDK (client-side encrypted, for MPC mode)
```

## Service Secrets API (2026-04-13)

Server-side encrypted secrets for service-to-service use. Unlike ZK secrets
(client-side encrypted via MPC), these are encrypted at rest by Base and
decrypted by KMS on read. Services authenticate via IAM JWT (service account).

**Routes (authenticated):**
- `PUT /v1/kms/orgs/{org}/secrets/{path}/{name}` — create/update (admin only)
- `GET /v1/kms/orgs/{org}/secrets/{path}/{name}` — fetch plaintext value
- `DELETE /v1/kms/orgs/{org}/secrets/{path}/{name}` — delete (admin only)
- `GET /v1/kms/orgs/{org}/secrets?prefix=...` — list names (no values)

**Client library:** `github.com/hanzoai/kms/pkg/kmsclient`
```go
c, _ := kmsclient.New(kmsclient.Config{
    Endpoint:     "http://kms:8443",
    IAMEndpoint:  "http://iam:8000",
    ClientID:     os.Getenv("IAM_CLIENT_ID"),
    ClientSecret: os.Getenv("IAM_CLIENT_SECRET"),
    Org:          "liquidity",
})
val, _ := c.Get(ctx, "providers/alpaca/dev", "api_key")
c.Put(ctx, "providers/alpaca/dev", "api_key", "NEW_VALUE")
```

**CLI:**
```bash
kms-cli put providers/alpaca/dev/api_key VALUE --org liquidity
kms-cli get providers/alpaca/dev/api_key --org liquidity
kms-cli list providers --org liquidity
kms-cli rotate providers/alpaca/dev/api_key NEW_VALUE --org liquidity
```

**Collection:** `kms_service_secrets` (org_id, path, name, value; unique on org+path+name).

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
