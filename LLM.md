# Hanzo KMS

**Last Updated**: 2026-04-23
**Repo**: github.com/hanzoai/kms
**Module**: github.com/hanzoai/kms (Go 1.26.1)

## What this is

A thin Hanzo-branded wrapper over `github.com/luxfi/kms`. The Go server,
secret store, MPC client, ZAP secrets server, and S3 replicator all come
from luxfi/kms. This module owns three things:

1. `cmd/kmsd` — the daemon. Wires luxfi/kms primitives with Hanzo defaults
   (port 8443, `/data/hanzo-kms`, IAM at `https://hanzo.id`) and adds
   Hanzo-specific JWT verification, audit log, version CAS, header hygiene.
2. `cmd/kms` — the admin CLI (`kms put|get|list|rotate|status`).
3. `pkg/kmsclient` — the Go client used by every other Hanzo service to
   fetch secrets at runtime (HTTP + ZAP fallback).

There is **no Infisical** in this repo. There is **no Base/SQLite**. There
is **no PostgreSQL** in the canonical Go module. Everything that used to
live in `internal/handler/`, `internal/store/`, `internal/server/` has been
deleted in favour of the upstream `github.com/luxfi/kms/pkg/{store,keys,
mpc,zapserver}` packages. The `frontend/` and `ui/` trees are legacy React
assets shipped as static files; they do not affect the API surface.

## Architecture

```
                     ┌──────────────────────────────┐
                     │   Hanzo IAM (hanzo.id)       │
                     │   RFC 6749 + OIDC, JWKS      │
                     └──────────────┬───────────────┘
                          OAuth2 / JWT (RS256)
                                    │
        ┌───────────────────────────▼──────────────────────────┐
        │                        kmsd                          │
        │  HTTP :8443    (mux: /v1/kms/* only)                 │
        │  ZAP  :9999    (binary, opcodes 0x0040..0x0043)      │
        │                                                       │
        │  cmd/kmsd/main.go      ← wiring + routes              │
        │  cmd/kmsd/auth.go      ← JWT verify (RFC 7519)        │
        │  cmd/kmsd/jwks.go      ← JWKS cache + RSA resolve     │
        │  cmd/kmsd/audit.go     ← per-request audit ledger     │
        │  cmd/kmsd/versioning.go← per-secret version CAS       │
        │                                                       │
        │  github.com/luxfi/kms/pkg/store    ← secret CRUD      │
        │  github.com/luxfi/kms/pkg/keys     ← MPC key mgr      │
        │  github.com/luxfi/kms/pkg/mpc      ← MPC client       │
        │  github.com/luxfi/kms/pkg/zapserver← ZAP transport    │
        └──────────────┬───────────────────────────────────────┘
                       │
        ┌──────────────▼─────────────┐    ┌─────────────────────┐
        │   ZapDB (encrypted, LSM)   │───▶│   S3 (age-encrypted)│
        │   $KMS_DATA_DIR            │    │   1s incremental    │
        └────────────────────────────┘    └─────────────────────┘
```

## Routes (canonical, exhaustive)

All routes live under `/v1/kms`. There is no `/api/`. There are no aliases.

### Public

| Method | Path                  | Notes                                  |
|--------|-----------------------|----------------------------------------|
| GET    | `/healthz`            | Liveness, no auth                      |
| POST   | `/v1/kms/auth/login`  | Machine-identity client credentials    |

`POST /v1/kms/auth/login` exchanges `clientId`+`clientSecret` for an IAM
access token by proxying to IAM's OAuth token endpoint
(`POST $IAM_ENDPOINT/api/login/oauth/access_token`). The response is a
plain `{accessToken, expiresIn, tokenType}` envelope. Outbound `/api/`
is the IAM (Casdoor) compatibility surface — not a route this service
exposes.

### Secrets (per-org, JWT-gated)

| Method | Path                                                  |
|--------|-------------------------------------------------------|
| GET    | `/v1/kms/orgs/{org}/secrets/{path...}/{name}?env=…`   |
| POST   | `/v1/kms/orgs/{org}/secrets`                          |
| PATCH  | `/v1/kms/orgs/{org}/secrets/{path...}/{name}`         |
| DELETE | `/v1/kms/orgs/{org}/secrets/{path...}/{name}?env=…`   |

- Authorization: `Authorization: Bearer <jwt>` from Hanzo IAM. Token's
  verified `owner` claim must equal the URL `{org}` segment, OR the token
  must carry an admin role (`superadmin`, `kms-admin`, `admin`).
- POST is upsert: bumps version, no CAS.
- PATCH is update-only and **requires** version CAS via either the
  `If-Match: <int>` header or `body.version`. Missing both → 428.
  Mismatch → 409 with the current version. Replay defence is structural,
  not advisory.
- DELETE wipes the version record so a recreate restarts from 1.

### Admin-only

| Method | Path                       | Use                                  |
|--------|----------------------------|--------------------------------------|
| GET    | `/v1/kms/secrets/{name}`   | Process env-var fetch (env-backed)   |
| GET    | `/v1/kms/audit/stats`      | Background auditor counters          |

These require an admin role claim. The env-backed fetch is intended only
for in-cluster bootstrap of services that read their own env vars before
KMS is reachable.

### MPC keys (only when `MPC_VAULT_ID` is set)

| Method | Path                            | Use                          |
|--------|---------------------------------|------------------------------|
| POST   | `/v1/kms/keys/generate`         | DKG a validator key set      |
| GET    | `/v1/kms/keys`                  | List validator key sets      |
| GET    | `/v1/kms/keys/{id}`             | Get one key set              |
| POST   | `/v1/kms/keys/{id}/sign`        | Threshold sign (BLS or RT)   |
| POST   | `/v1/kms/keys/{id}/rotate`      | Reshare keys                 |
| GET    | `/v1/kms/status`                | KMS+MPC liveness             |

All require admin role. Threshold signing delegates to luxfi/mpc over ZAP
(or HTTP fallback) at `MPC_ADDR`.

## Auth contract (`cmd/kmsd/auth.go`)

Full RFC 7519 enforcement, no escape hatches:

1. `Authorization: Bearer <token>` else 401.
2. `alg ∈ {RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, EdDSA}`. **No HS\*. No `none`.**
3. Signature verifies against JWKS by `kid`.
4. `iss == $KMS_EXPECTED_ISSUER`.
5. `aud` ⊇ one of `$KMS_EXPECTED_AUDIENCE` (comma list ok).
6. `exp > now`, leeway 0.
7. `nbf ≤ now` if present.
8. `sub` (or `id`) present.

Failure → 401 with body `{"message":"unauthorized"}`. The structured audit
log records the failure class (`alg_not_allowed`, `expired`, `wrong_iss`,
`wrong_aud`, `sig_invalid`, `missing_sub`, `no_bearer`, `misconfigured`).
No claim is echoed to the client body or logs.

`KMS_ENV ∈ {dev,devnet,local}` is the **only** mode where missing
`KMS_EXPECTED_ISSUER`/`KMS_EXPECTED_AUDIENCE`/`KMS_JWKS_URL` is tolerated.
In any other mode `validateAuthConfigAtBoot` refuses to start.

### Header hygiene

`stripIdentityHeaders` deletes every inbound identity header before mux
dispatch. The handler trusts only what the verified JWT says. Killed
headers include `X-User-Id`, `X-Org-Id`, `X-Roles`, `X-Hanzo-*`,
`X-IAM-*`, `X-Tenant-Id`, `X-Is-Admin`, `X-Gateway-*`, etc.

`methodAllowlist` rejects `TRACE`, `CONNECT`, `OPTIONS` at the edge.

## Storage

- **At rest**: ZapDB (Badger-derived LSM) at `$KMS_DATA_DIR`. Optional
  AES-GCM encryption via `KMS_ENCRYPTION_KEY_B64` (32 raw bytes b64).
- **Replication**: in-process `badger.Replicator` streaming age-encrypted
  incremental + snapshot backups to S3. Off when `REPLICATE_S3_ENDPOINT`
  is empty.
- **Audit**: side-table SQLite at `$KMS_AUDIT_DB` (default
  `/tmp/kms-aux.db`). Buffered, single writer, never blocks request path.

The luxfi `pkg/store.SecretStore` handles the on-disk envelope:
per-secret 256-bit DEK, DEK wrapped under master key (AES-256-GCM).

## ZAP binary transport

Sub-100µs in-cluster secret CRUD on port `KMS_ZAP_PORT` (default 9999).
Disabled unless `KMS_MASTER_KEY_B64` is set (32 raw bytes b64). Same
authorization model as HTTP — JWT via the same JWKS, identical role
checks. Service discovery via mDNS (`_kms._tcp`).

## Env vars

| Var                          | Default                          | Required          |
|------------------------------|----------------------------------|-------------------|
| `KMS_LISTEN`                 | `:8443`                          | no                |
| `KMS_ZAP_PORT` / `KMS_ZAP`   | `9999`                           | no                |
| `KMS_DATA_DIR`               | `/data/hanzo-kms`                | no                |
| `KMS_NODE_ID`                | `hanzo-kms-0`                    | no                |
| `KMS_ENV`                    | `dev`                            | yes (`prod`/`main`) |
| `KMS_EXPECTED_ISSUER`        | —                                | yes (non-dev)     |
| `KMS_EXPECTED_AUDIENCE`      | `kms`                            | yes (non-dev)     |
| `KMS_JWKS_URL`               | —                                | yes (non-dev)     |
| `KMS_ENCRYPTION_KEY_B64`     | —                                | recommended       |
| `KMS_MASTER_KEY_B64`         | —                                | required for ZAP  |
| `KMS_AUDIT_DB`               | `/tmp/kms-aux.db`                | no                |
| `IAM_ENDPOINT`               | `https://hanzo.id`               | no                |
| `MPC_ADDR`                   | mDNS                             | no (mDNS-discoverable) |
| `MPC_VAULT_ID`               | —                                | no (key routes off) |
| `REPLICATE_S3_*`             | —                                | no (replication off) |

## Build

```bash
make            # builds ./kmsd and ./kms
make test       # go test ./...
```

CI: `hanzoai/.github/.github/workflows/docker-build.yml@main` builds
`ghcr.io/hanzoai/kms:<branch>` for `linux/amd64` + `linux/arm64` on
native runners (DO+GKE), no QEMU.

## Where things live

```
cmd/kms/        admin CLI
cmd/kmsd/       daemon (this is the production binary)
pkg/kmsclient/  Go client used by other Hanzo services
sdk/go/         legacy ZK client SDK (separate module)
mpc-node/       standalone MPC node (separate module)
frontend/       legacy React UI (static, served as-is)
ui/             new admin UI (build artefact, optional)
```

Everything in `cmd/kmsd` and `pkg/kmsclient` is **the** active surface.
Everything in `frontend/`, `ui/`, `docs/`, `examples/`, `mpc-node/`, and
`sdk/go/` is supporting and not on the request path.

## Operator protocol delta (open)

`~/work/hanzo/universe/infra/k8s/paas/secrets.yaml` ships `KMSSecret`
resources (`secrets.lux.network/v1alpha1`) with:
- `spec.hostAPI: http://kms.hanzo.svc.cluster.local/api`
- `spec.authentication.universalAuth.secretsScope.{projectSlug,envSlug,secretsPath}`

This shape was minted for the Infisical era. The current `kmsd` only
serves `/v1/kms/*` and uses `org/secrets/{path}/{name}?env=…` — there is
no `/api/v3/secrets/raw` and no `projectSlug`/`envSlug` model. The
operator that reconciles `KMSSecret` resources must be updated to call
the canonical surface; the KMS will not grow a back-compat shim. Tracked
separately — this module does not touch the operator.

## Rules

- One canonical path per operation. No aliases.
- Every endpoint requires IAM JWT or an explicit admin role.
- `KMS_ENV` other than `dev`/`devnet`/`local` refuses to boot without
  full JWT config.
- All secrets at rest are encrypted (envelope DEK + master key).
- Passwords are never stored in this service. Identity lives in IAM.
  When IAM stores a password, it is bcrypt-hashed (cost ≥ 12).
- No backwards compatibility. No env flags for "use Infisical instead."
