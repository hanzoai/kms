# Hanzo KMS — agent guide

**Repo**: `github.com/hanzoai/kms` · **Module**: `github.com/hanzoai/kms` (Go 1.26)

## What this is

The canonical secret store + threshold-signing service for every Hanzo deployment.
A **thin Go wrapper over `github.com/luxfi/kms`** (v1.11.x) + `luxfi/mpc` — all server
logic lives upstream; this module wires those primitives with Hanzo defaults and adds
JWT verification and header hygiene. The root package
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

## How this ships

One way, and it runs on our own stack:

    push  ->  github.com/hanzoai/kms          (a mirror)
              .github/workflows/sync.yml       carries refs onward
      ->  git.hanzo.ai/hanzoai/kms             CANONICAL
              .hanzo/workflows/ci.yml          go test -race + builds kmsd/kms
              .hanzo/workflows/build.yml       ghcr.io/hanzoai/kms on main
              .hanzo/workflows/release.yml     v* tags: binaries + release + image
              .hanzo/workflows/build-kms-fetch.yml  ghcr.io/hanzoai/kms-fetch
              .hanzo/workflows/check-fe-ts-and-lint.yml  frontend typecheck on PRs
              .hanzo/workflows/pr-preview.yml  ephemeral PR preview env

**git.hanzo.ai is canonical; GitHub is a mirror.** `.github/workflows/` holds
exactly one file, `sync.yml`, and its only job is getting refs to the forge. Every
build, check and deploy is a workflow under `.hanzo/workflows/`, which the forge
reads. `.hanzo/workflows` uses GitHub Actions syntax, so a workflow moves between
the two by changing directory and nothing else.

`ci.yml`, `release.yml` and `check-fe-ts-and-lint.yml` had been deleted from
`.github/workflows` with no replacement anywhere — which silently removed the
repo's only gate and the only producer of the release binaries and semver image
tags, with no red run to show it, because a workflow that does not exist cannot
fail. They are restored here at the path the forge reads.

`release.yml` is the heaviest lane: a 4-way binary matrix
(linux/darwin × amd64/arm64) for `cmd/kms` + `cmd/kmsd`, a GitHub Release with
12 assets, a multi-arch `ghcr.io/hanzoai/kms:{vX.Y.Z, X.Y.Z, latest}`, and a
final best-effort `notify-universe` job. That last job is
`continue-on-error: true`, so a missing `UNIVERSE_DISPATCH_TOKEN` on the forge
degrades to a yellow job and never fails the release.

`build.yml`, `build-kms-fetch.yml` and `pr-preview.yml` are thin callers of
`hanzoai/.github/.github/workflows/*@main`. Those references resolve by path, so
they break the day the reusable workflows themselves move to `.hanzo/workflows` —
worth inlining then, not now.

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
consensus.go    signed consensus-authority snapshot → ZAP authorizer (fail-closed)
```

## Routes — all under `/v1/kms`, no `/api/`, no aliases

| Method | Path | Notes |
|--------|------|-------|
| GET  | `/healthz` | liveness, no auth |
| POST | `/v1/kms/auth/login` | machine-identity client creds → IAM token (proxies `POST $IAM_ENDPOINT/v1/iam/oauth/token`) |
| GET  | `/v1/kms/health` | liveness, no auth |
| GET  | `/` | dashboard SPA (its secret views call cloud) |

**No secret plane, no key plane, no `roles` claim.** The HTTP secret CRUD that used to live
here authorized on the `{org}` URL segment while the ZapDB key
(`kms/secrets/{path}/{env}/{name}`) carried no org — so any authenticated tenant could read
and overwrite any other tenant's record by naming it in the path, and `GET
/v1/kms/secrets/{name}` returned any process env var including the master key. Both are
deleted, along with the `isAdmin()`/`roles` predicate that gated the env read, the audit-stats
route, and the MPC key routes (whose only gate was that same predicate).

Secrets over HTTP are `cloud/apps/kms`: `/v1/kms/orgs/{org}/secrets/…`, org folded into the
storage key via `orgPath()` so a path cannot escape its tenant. Authorization is IAM's, per
the architecture rule — a secret store does not invent its own. In-cluster reads use the ZAP
transport, whose authorizer is a signed consensus-authority snapshot (`consensus.go`) and
which stays off unless that snapshot is present. `TestSecretHTTPPlaneIsAbsent` is the
regression guard.

## Auth contract (`auth.go`) — RFC 7519, no escape hatches

Bearer JWT from Hanzo IAM (brand issuer, e.g. `hanzo.id`). `alg` ∈ RS/ES/PS/EdDSA — **no
HS\*, no `none`**. Verify sig against JWKS by `kid`; check `iss`, `aud`, `exp`, `nbf`, `sub`.
Failure → `401 {"message":"unauthorized"}`; no claim echoed. `stripIdentityHeaders` deletes
every inbound `X-User-Id`/`X-Org-Id`/`X-Roles`/`X-*-*` before dispatch — the handler trusts
only the verified JWT. `methodAllowlist` rejects TRACE/CONNECT/OPTIONS at the edge.

## Storage

ZapDB (LSM) at `$KMS_DATA_DIR`, per-secret 256-bit DEK wrapped under the master key
(AES-256-GCM); optional volume encryption via `KMS_ENCRYPTION_KEY_B64`. Age-encrypted
incremental + snapshot replication to S3 (`REPLICATE_S3_*`, off when unset). ZAP binary transport (`KMS_ZAP_PORT`, needs
`KMS_MASTER_KEY_B64`) carries the secret plane, gated by the consensus authorizer; mDNS
`_kms._tcp`.

## Rules

- One canonical path per operation. This surface authorizes nothing: IAM owns identity and
  permissions, so no route here reads a `roles` claim or compares an org. Secret
  authorization is cloud's (`apps/kms`, org folded into the storage key).
- All secrets encrypted at rest (envelope DEK + master key). No plaintext passwords —
  identity lives in IAM (bcrypt cost ≥ 12 there).
- No backwards-compat shims, no "use the legacy backend" flags. Forward-only.
- Specs: HIP-0027 (KMS), HIP-0106 (unified cloud binary), HIP-0302 (encrypted durability),
  HIP-0026 (IAM). Upstream attribution retained in `LICENSE` + `NOTICE` (Infisical, MIT).

---

Hanzo — the Open AI Cloud · [hanzo.ai](https://hanzo.ai) · [docs.hanzo.ai](https://docs.hanzo.ai) · umbrella [hanzoai/sdk](https://github.com/hanzoai/sdk)
