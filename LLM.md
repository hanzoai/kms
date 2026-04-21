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

8443 (HTTP). 9653 (ZAP binary, optional). Matches K8s service port convention for KMS across the platform.

### ZAP Binary Transport (optional)

Sub-100us in-cluster secret CRUD over the [`luxfi/zap`](https://github.com/luxfi/zap)
binary protocol. Same authorization model as HTTP (IAM JWT validated against the
same JWKS, identical role checks). No auth-disabled mode on the binary transport —
the server refuses to start without a JWKS validator.

```
KMS_ZAP=":9653"   # bind addr; empty disables, default :9653
```

Opcodes (see `internal/zapsrv/zapsrv.go`):

| Opcode | Operation       | Authz                              |
|--------|-----------------|------------------------------------|
| 0x0060 | secret resolve  | `canReadSecret(claims, tenantID)`  |
| 0x0061 | secret get      | `canReadSecret(claims, tenantID)`  |
| 0x0062 | secret create   | `isSecretAdmin(claims, tenantID)`  |
| 0x0063 | secret update   | `isSecretAdmin(claims, tenantID)`  |
| 0x0064 | secret delete   | `isSecretAdmin(claims, tenantID)`  |

Wire format: single root object per request/response, fixed byte offsets,
big-endian per zap library convention. Token is carried at field 0; tenant/secret
identifiers and payloads occupy slots 8/16/24/32. Audit log entries get
`transport: "zap"` so HTTP vs ZAP traffic can be distinguished after the fact.

Go SDK: `pkg/kmsclient` ships a drop-in three-arg `New(...)` with optional
`ZapAddr`. On any ZAP failure (decode, timeout, disconnect, non-200) the client
falls back transparently to HTTP — same behavior as the `hanzo/tasks` SDK.

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
| KMS_AUTH_MODE | yes | "iam" (prod, default) or "none" (dev only, requires KMS_DEV_MODE=true) |
| HANZO_IAM_JWKS_URL | yes (iam) | JWKS endpoint for JWT validation (per-env) |
| HANZO_IAM_EXPECTED_ISSUER | yes (iam) | Required `iss` claim value (per-env, no cross-env trust) |
| HANZO_IAM_EXPECTED_AUDIENCE | no | Required `aud` claim value (default "kms") |
| HANZO_IAM_LEEWAY_SECONDS | no | Clock skew tolerance, 0..5, default 0 |
| KMS_DEV_MODE | no | "true" to allow KMS_AUTH_MODE=none (dev only) |
| APP_NAME | no | UI display name (default "KMS") |
| KMS_FRONTEND_DIR | no | Path to React frontend dist (default /app/frontend) |
| DISABLE_ADMIN_UI | no | "true" to block /_/ admin |
| MPC_ADDR | no | ZAP address for MPC backend |
| MPC_VAULT_ID | no | MPC vault ID (empty = secrets-only mode) |

### JWT validation — per-env trust boundary (2026-04-21)

KMS enforces the following on every sensitive route:

- `iss` MUST equal `HANZO_IAM_EXPECTED_ISSUER` exactly. No prefix matching,
  no multi-issuer list. A dev-minted token CANNOT authenticate to test or
  main, and vice versa.
- `exp` MUST be in the future. Zero clock skew by default (configurable up
  to 5s maximum). A 30s-expired token is rejected — short-lived tokens are
  already ephemeral, NTP drift is not an auth policy.
- `aud` MUST contain `HANZO_IAM_EXPECTED_AUDIENCE` (default "kms"). A token
  minted for ATS cannot access KMS.
- `kid` MUST resolve against the env-specific JWKS at `HANZO_IAM_JWKS_URL`.
  No shared keyrings across envs. kid-shadowing (signing with key A,
  claiming kid of key B) is rejected at signature verify.
- `alg` MUST be one of RS256/RS384/RS512/ES256/ES384/ES512. `alg=none` and
  HS* are rejected at parse time — no algorithm confusion.

Per-env config:
- dev:  `HANZO_IAM_EXPECTED_ISSUER=https://iam.dev.satschel.com`,  `aud=kms`
- test: `HANZO_IAM_EXPECTED_ISSUER=https://iam.test.satschel.com`, `aud=kms`
- main: `HANZO_IAM_EXPECTED_ISSUER=https://iam.main.satschel.com`, `aud=kms`

Fail-safe: with `KMS_AUTH_MODE=iam` (default), a missing `HANZO_IAM_JWKS_URL`
or `HANZO_IAM_EXPECTED_ISSUER` causes `log.Fatalf` at startup. KMS cannot
silently degrade to unauthenticated.

Implementation: `pkg/auth/jwt.go` (`Validator.Middleware`). Wired in
`cmd/kmsd/main.go` via the `protect` closure around every sensitive route.
Unauthenticated-on-purpose routes: `GET /healthz` (liveness probe),
`POST /v1/kms/auth/login` (exchanges client_credentials for a token — you
can't hold a token before you have one).

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
