# IAM JWT Authentication

Hanzo KMS does not own user identity. Every authenticated request must
carry an Authorization: Bearer JWT issued by Hanzo IAM (hanzo.id).

KMS verifies the token, derives the caller's org and roles from the
verified claims, and authorizes against those claims directly — there is
no local user table, no local password, no local session.

## Contract (RFC 7519, no escape hatches)

A request is accepted only if **all** of the following hold:

| # | Check                                              | Failure class      |
|---|----------------------------------------------------|--------------------|
| 1 | `Authorization: Bearer <token>` header present     | `no_bearer`        |
| 2 | `header.alg` ∈ {RS\*, ES\*, PS\*, EdDSA}           | `alg_not_allowed`  |
| 3 | Signature verifies against IAM JWKS by `kid`       | `sig_invalid`      |
| 4 | `iss` claim equals `$IAM_ISSUER`                   | `wrong_iss`        |
| 5 | `aud` claim contains one of `$IAM_AUDIENCE` (CSV)  | `wrong_aud`        |
| 6 | `exp` > now (leeway 0)                             | `expired`          |
| 7 | `nbf` ≤ now (when present)                         | `expired`          |
| 8 | `sub` (or `id`) claim present                      | `missing_sub`      |

Any failure → HTTP 401 with body `{"message":"unauthorized"}`.

The failure class is recorded in the audit log (`kms_auth_reject`) but
**never echoed to the client body** — generic body avoids oracle attacks.

`HS*` algorithms and `alg=none` are unconditionally rejected. Red Team
demonstrated a 3-line `alg=none` bypass on 2026-04-21; the defence is
asymmetric-only `WithValidMethods` plus a belt-and-braces "none" string
check in the keyfunc.

## Claim → RBAC mapping

After verification, KMS extracts four claims from the JWT and maps them
to operations:

```go
type jwtClaims struct {
    Iss   string   // issuer (audit only)
    Owner string   // organization slug (org scope)
    Sub   string   // user id (audit + actor_id)
    Roles []string // role names (admin gate)
}
```

| Operation                                                     | Required claim |
|---------------------------------------------------------------|----------------|
| `GET /v1/kms/orgs/{org}/secrets/{path}/{name}?env=...`        | `owner == {org}` OR admin role |
| `POST /v1/kms/orgs/{org}/secrets`                             | `owner == {org}` OR admin role |
| `PATCH /v1/kms/orgs/{org}/secrets/{path}/{name}`              | `owner == {org}` OR admin role |
| `DELETE /v1/kms/orgs/{org}/secrets/{path}/{name}`             | `owner == {org}` OR admin role |
| `GET /v1/kms/secrets/{name}` (process env var fetch)          | admin role     |
| `GET /v1/kms/audit/stats`                                     | admin role     |
| `POST /v1/kms/keys/generate` (MPC, when enabled)              | admin role     |
| `GET  /v1/kms/keys`                                           | admin role     |
| `GET  /v1/kms/keys/{id}`                                      | admin role     |
| `POST /v1/kms/keys/{id}/sign`                                 | admin role     |
| `POST /v1/kms/keys/{id}/rotate`                               | admin role     |
| `GET  /v1/kms/status`                                         | admin role     |
| `GET  /healthz`, `GET /v1/kms/health`                         | **public**     |
| `POST /v1/kms/auth/login` (client_credentials proxy to IAM)   | **public**     |

Admin role = one of {`superadmin`, `kms-admin`, `admin`} (case-insensitive)
in the verified `roles` claim. The `owner` claim is a **scope** field,
not a privilege flag — `owner=="admin"` does NOT grant cross-tenant
access (Red Team F7 fix, 2026-04-21).

## Environment variables

KMS refuses to boot (any `KMS_ENV` other than `dev`/`devnet`/`local`)
unless all four are set:

| Var           | Example                                | Purpose                              |
|---------------|----------------------------------------|--------------------------------------|
| `IAM_URL`     | `https://hanzo.id`                     | IAM origin (used by /auth/login proxy) |
| `IAM_ISSUER`  | `https://hanzo.id`                     | Expected `iss` claim                 |
| `IAM_AUDIENCE`| `kms,hanzo-kms,hanzo-cloud`            | Expected `aud` claim (CSV ok)        |
| `IAM_KEYS_URL`| `https://hanzo.id/.well-known/jwks`    | JWKS endpoint (cached 15min)         |
| `KMS_ENV`     | `prod` / `dev` / `devnet` / `local`    | dev/devnet/local relax the boot gate |

In `dev`/`devnet`/`local` the same env vars are still **honoured** when
present — they only stop being mandatory at boot. The verify step never
relaxes.

## How a caller obtains an IAM JWT

Three paths, all RFC 6749:

### 1. Authorization Code (web user)
A signed-in IAM session can be exchanged at IAM's `/oauth/token` for a
JWT scoped to the consuming service (this KMS instance has audience
`hanzo-kms` or one of the CSV entries in `IAM_AUDIENCE`).

### 2. Client Credentials (service account)
```
curl -s -X POST 'https://hanzo.id/v1/iam/oauth/token' \
  -d 'grant_type=client_credentials' \
  -d "client_id=<svc>" \
  -d "client_secret=<secret>" \
  -d 'scope=openid'
```

`v1/iam/oauth/token` returns `{access_token, ...}`. The KMS-hosted
proxy at `POST /v1/kms/auth/login` does the same exchange via
`POST $IAM_URL/v1/iam/login/oauth/access_token` and unwraps to
`{accessToken, expiresIn, tokenType}` for legacy clients.

### 3. Device Code (CLI)
`POST $IAM_URL/oauth/device` → poll → token. Same RS256 JWT, same
claims, accepted by KMS unchanged.

## End-to-end smoke test

```bash
# 1. Get a service-account JWT via client_credentials
TOK=$(curl -s -X POST 'https://hanzo.id/v1/iam/oauth/token' \
        -d 'grant_type=client_credentials' \
        -d 'client_id=hanzo-kms' \
        -d "client_secret=$KMS_CLIENT_SECRET" \
        -d 'scope=openid' | jq -r .access_token)

# 2. Read a secret in the caller's org (success path).
curl -s -H "Authorization: Bearer $TOK" \
  "https://kms.hanzo.ai/v1/kms/orgs/hanzo/secrets/prod/app/db_url?env=prod"

# 3. Cross-tenant attempt (failure path): expect 403.
curl -s -H "Authorization: Bearer $TOK" \
  "https://kms.hanzo.ai/v1/kms/orgs/zoo/secrets/prod/app/db_url?env=prod"

# 4. No auth (failure path): expect 401.
curl -s "https://kms.hanzo.ai/v1/kms/orgs/hanzo/secrets/prod/app/db_url?env=prod"
```

## Header hygiene

The Hanzo gateway injects `X-User-Id`, `X-Org-Id`, `X-Roles` after its
own JWT verification. **KMS strips every identity header before
dispatch** (`stripIdentityHeaders` in embed.go) and re-derives identity
from the verified JWT only. This is belt-and-braces: a bypass of the
gateway boundary cannot smuggle spoofed identity into KMS.

Killed inbound headers include: `X-User-Id`, `X-Org-Id`, `X-Roles`,
`X-User-Email`, `X-Gateway-*`, `X-Hanzo-*`, `X-IAM-*`, `X-User-Role`,
`X-User-Roles`, `X-Tenant-Id`, `X-Is-Admin`.

## Audit ledger

Every authorize() call (success or failure) emits one row to the
`kms_audit` SQLite ledger at `$KMS_AUDIT_DB`:

```
ts          actor_id      iss            sub                method  path                                 result   secret  env  ver
2026-05-19  iss:sub-comp  hanzo.id       6c1f...           GET     /v1/kms/orgs/hanzo/secrets/prod/k    200      prod/k  prod 7
2026-05-19  unknown       —              —                 GET     /v1/kms/orgs/hanzo/secrets/prod/k    401      —       —    0
```

`actor_id` is `iss:sub` so the same Casdoor user across multiple
issuers is still distinguishable. The auditor is buffered + async; it
never blocks the request path.

## Break-glass auth

There is no separate break-glass user in KMS. The break-glass path is:

1. Hanzo IAM's `superadmin` user grants a one-off `kms-admin` role to a
   short-lived service account.
2. The service account mints a JWT via client_credentials.
3. The JWT carries `roles: ["kms-admin"]` → KMS treats it as admin
   regardless of `owner`.
4. Audit log records the JWT's `sub` so the break-glass usage is
   attributable.

Rotating the break-glass account = rotating the IAM client_secret +
revoking the role assignment in IAM. KMS does not need a redeploy.

## Troubleshooting

| Symptom                              | First thing to check                                        |
|--------------------------------------|-------------------------------------------------------------|
| `401 unauthorized` on every request  | `kubectl exec ... -- env \| grep IAM_` — all four set?      |
| `401` only after key rotation        | JWKS cache TTL is 15min; wait or restart pod                |
| `403 org claim does not match URL`   | JWT's `owner` ≠ URL `{org}` segment; check token contents   |
| `401 wrong_aud`                       | Add the missing audience to `IAM_AUDIENCE` CSV               |
| `401 sig_invalid`                    | Token was signed by a different IAM (wrong `IAM_KEYS_URL`)  |
| Boot loop                            | `kms.Embed: auth config: IAM_* required` — wire env vars    |

To inspect a token without exposing it: `jwt decode <token>` (don't
paste into chat; tokens carry session identity).

## See also

- `~/work/hanzo/kms/auth.go` — verifyJWT() RFC 7519 enforcement
- `~/work/hanzo/kms/jwks.go` — JWKS cache (15min TTL, fail-closed)
- `~/work/hanzo/kms/embed.go` — jwtClaims, canActOnOrg, isAdmin, route gates
- `~/work/hanzo/kms/jwt_test.go` — F1..F7 regression suite (Red Team)
- `~/work/hanzo/universe/infra/k8s/hanzo-operator/crs/hanzo-platform.yaml` — cluster wiring
