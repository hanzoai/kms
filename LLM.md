# Hanzo KMS — agent guide

**Repo**: `github.com/hanzoai/kms` · **Module**: `github.com/hanzoai/kms` (Go 1.26)

## What this is

The canonical secret store + threshold-signing service for every Hanzo deployment.
A **thin Go wrapper over `github.com/luxfi/kms`** (v1.11.x) + `luxfi/mpc` — all server
logic lives upstream; this module wires those primitives with Hanzo defaults and adds
JWT verification, the audit ledger, version CAS, and header hygiene. The root package
`kms` mounts into the unified cloud binary via `kms.Mount(app, deps)` (HIP-0106) and
also ships as the standalone `cmd/kmsd` daemon. There is **no** Node fork, **no**
PostgreSQL, **no** Base — the legacy `internal/{handler,store,server}` tree is gone.

## Canonical role (Hanzo SDK model)

This is a **product/service repo** (`hanzoai/<product>`) — the canonical impl of KMS.
Its Go client lives in-repo at `sdk/go` (module `github.com/hanzoai/kms/sdk/go`) and is
what every other Hanzo service imports to fetch secrets. Full model:
`~/work/hanzo/SDK-ARCHITECTURE.md` (one impl one place; discovery repos link out).

## Brand rules (hard)

- Never call Hanzo an "LLM gateway" and never position against LiteLLM — it is a full
  **AI cloud**, not a proxy. Purge that framing on sight.
- Paths are `/v1/…` only — **never** `/api/`. One canonical path per op, no aliases.
- Zen models are our own family — never name upstream models.
- Voice: "Hanzo — the Open AI Cloud." Modern, crisp, developer-first.

## Build / run

```bash
make kmsd kms          # ./kmsd (daemon) + ./kms (admin CLI: put|get|list|rotate|status)
make test              # go test ./...
KMS_ENV=dev ./kmsd     # HTTP :8443, ZAP :9999 (dev tolerates missing JWT config)
```

Non-`dev`/`devnet`/`local` `KMS_ENV` refuses to boot without
`KMS_EXPECTED_ISSUER` + `KMS_EXPECTED_AUDIENCE` + `KMS_JWKS_URL`. Fail-closed.
CI: `hanzoai/.github/.github/workflows/docker-build.yml@main` → `ghcr.io/hanzoai/kms`,
`linux/amd64` on the `hanzo-build-linux-amd64` ARC pool, semver `v*` tags (never `:latest`).

## Entry points

```
cmd/kmsd/       production daemon (config via cloud.LoadConfig → kms.Mount)
cmd/kms/        admin CLI
cmd/kms-fetch/  one-shot bootstrap fetch (see Dockerfile.kms-fetch)
cmd/smoke-zap/  ZAP transport smoke test
sdk/go/         kmsclient — Go client (HTTP + ZAP fallback) used by all services
frontend/       static TS dashboard (built in a separate Docker stage)
embed.go        root pkg: server assembly, routes, embedded frontend
auth.go jwks.go per-request JWT verify (RFC 7519) + JWKS cache
audit.go        buffered audit ledger (SQLite side-table, never blocks the path)
```

## Routes — all under `/v1/kms`, no `/api/`, no aliases

| Method | Path | Notes |
|--------|------|-------|
| GET  | `/healthz` | liveness, no auth |
| POST | `/v1/kms/auth/login` | machine-identity client creds → IAM token (proxies `POST $IAM_ENDPOINT/v1/iam/oauth/token`) |
| GET/POST/PATCH/DELETE | `/v1/kms/orgs/{org}/secrets/{path…}/{name}?env=…` | per-org, JWT-gated (token `owner` must equal `{org}` or carry an admin role) |
| GET  | `/v1/kms/secrets/{name}` · `/v1/kms/audit/stats` | admin-only: env-backed bootstrap fetch + auditor counters |
| POST | `/v1/kms/keys/generate` · `/{id}/sign` · `/{id}/rotate` | MPC DKG / threshold sign / reshare (admin; only when `MPC_VAULT_ID` set) |
| GET  | `/v1/kms/keys` · `/{id}` · `/v1/kms/status` | MPC key sets + liveness |

- **R-ENV (one-way env):** `env` is part of the storage key (`kms/secrets/{path}/{env}/{name}`)
  and can never be aliased. POST/PATCH **require an explicit `env`** — omitting it is a
  fail-loud `400`, never a silent `default`. `sdk/go` always sends `env`.
- **POST** = upsert (bumps version). **PATCH** = update-only, **requires** version CAS
  (`If-Match: <int>` or `body.version`): missing → 428, mismatch → 409 with current version.

## Auth contract (`auth.go`) — RFC 7519, no escape hatches

Bearer JWT from Hanzo IAM (brand issuer, e.g. `hanzo.id`). `alg` ∈ RS/ES/PS/EdDSA — **no
HS\*, no `none`**. Verify sig against JWKS by `kid`; check `iss`, `aud`, `exp`, `nbf`, `sub`.
Failure → `401 {"message":"unauthorized"}`; no claim echoed. `stripIdentityHeaders` deletes
every inbound `X-User-Id`/`X-Org-Id`/`X-Roles`/`X-*-*` before dispatch — the handler trusts
only the verified JWT. `methodAllowlist` rejects TRACE/CONNECT/OPTIONS at the edge.

## Storage

ZapDB (LSM) at `$KMS_DATA_DIR`, per-secret 256-bit DEK wrapped under the master key
(AES-256-GCM); optional volume encryption via `KMS_ENCRYPTION_KEY_B64`. Age-encrypted
incremental + snapshot replication to S3 (`REPLICATE_S3_*`, off when unset). Audit is a
buffered SQLite side-table (`$KMS_AUDIT_DB`). ZAP binary transport (`KMS_ZAP_PORT`, needs
`KMS_MASTER_KEY_B64`) mirrors HTTP under the identical JWT + role model; mDNS `_kms._tcp`.

## Rules

- One canonical path per operation; every endpoint needs an IAM JWT or admin role.
- All secrets encrypted at rest (envelope DEK + master key). No plaintext passwords —
  identity lives in IAM (bcrypt cost ≥ 12 there).
- No backwards-compat shims, no "use the legacy backend" flags. Forward-only.
- Specs: HIP-0027 (KMS), HIP-0106 (unified cloud binary), HIP-0302 (encrypted durability),
  HIP-0026 (IAM). Upstream attribution retained in `LICENSE` + `NOTICE` (Infisical, MIT).

---

Hanzo — the Open AI Cloud · [hanzo.ai](https://hanzo.ai) · [docs.hanzo.ai](https://docs.hanzo.ai) · umbrella [hanzoai/sdk](https://github.com/hanzoai/sdk)
