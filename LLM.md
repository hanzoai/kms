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
- `/v1/kms/keys/*` -- validator key management (authenticated)
- `/v1/kms/transit/*` -- encrypt/decrypt/sign/verify (authenticated)
- `/v1/kms/tenants/{tenantId}/secrets` -- tenant secret CRUD (returns secretId)
- `/v1/kms/tenants/{tenantId}/config` -- bindings + feature flags
- `/v1/kms/tenants/{tenantId}/integrations` -- provider bindings
- `/v1/kms/secrets/{secretId}` -- cross-tenant addressable read/update/delete
- `/v1/kms/audit` -- canonical audit query (filters via query params)
- `/v1/kms/auth/*` -- Infisical-compat stubs for frontend

One canonical path per operation. No org-scoped aliases. Forward perfection.

### R3-3: legacy /v1/kms/orgs/* DELETED (2026-04-18)

The following routes are gone. Requests return 404:

- `POST|GET /v1/kms/orgs/{org}/zk/secrets`
- `GET|DELETE /v1/kms/orgs/{org}/zk/secrets/{path}/{name}`
- `POST|GET|DELETE /v1/kms/orgs/{org}/members`
- `GET /v1/kms/orgs/{org}/audit`

Callers (none in ~/work) must migrate to `/v1/kms/tenants/{tenantId}/…`
and `/v1/kms/audit?tenantId=…`. The `kms_secrets` and `kms_members`
collections are no longer bootstrapped (existing data left untouched).

### F1: Postgres-backed audit concurrency test (2026-04-18)

`internal/store/audit_concurrency_pg_test.go` exercises the
`pg_advisory_xact_lock` path in `AuditStore.Append` directly. SQLite
serializes writes via the driver's write mutex, so the SQLite test never
touches the lock — a regression that removed the lock would still pass on
SQLite but break under concurrent Postgres load.

The PG test drives 10 concurrent writers × 10 inserts each against a real
Postgres 15 sidecar, using the exact advisory-lock SQL `audit.go` uses
(`SELECT pg_advisory_xact_lock(auditAdvisoryNamespace, orgAdvisoryKey(org))`
inside the tx before the tail read). Asserts:

- 100 entries, `seq` strictly 1..N with no gaps/dupes
- `prev_hash` chain is causal (`entry[i].prev_hash == entry[i-1].hash`)
- Side-channel `pg_locks` probe observes advisory-lock rows during the run
  (best-effort — documented fallback when the run is too fast for the probe)

CI wires a Postgres 15 sidecar in `.github/workflows/ci.yml` and sets
`TEST_PG_DSN=postgres://kms:kms@localhost:5432/kms_test?sslmode=disable`.
Locally the test skips unless `TEST_PG_DSN` is set — no silent drift.

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

## Service Secrets API (2026-04-18)

Server-side encrypted secrets for service-to-service use. Unlike ZK secrets
(client-side encrypted via MPC), these are encrypted at rest by Base and
decrypted by KMS on read. Services authenticate via IAM JWT (service account).

**Routes (authenticated) — one way only:**
- `POST /v1/kms/tenants/{tenantId}/secrets` — create (returns `secretId`)
- `GET /v1/kms/tenants/{tenantId}/secrets?path=&name=` — list / resolve
- `GET /v1/kms/secrets/{secretId}` — fetch plaintext value
- `PATCH /v1/kms/secrets/{secretId}` — update value
- `DELETE /v1/kms/secrets/{secretId}` — delete
- `POST /v1/kms/secrets/{secretId}/rotate` — append new version

The Go client `pkg/kmsclient` keeps the ergonomic `Get/Put/Delete/List(path,
name)` signatures but internally routes through the tenant list resolver +
canonical `secretId` endpoints.

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
