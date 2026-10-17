# Hanzo KMS — agent guide

**Repo**: `github.com/hanzoai/kms` · **Module**: `github.com/hanzoai/kms` (Go 1.26)

## What this is

The canonical secret store + threshold-signing service for every Hanzo deployment.
A **thin Go wrapper over `github.com/luxfi/kms`** (v1.11.x) + `luxfi/mpc` — all server
logic lives upstream; this module wires those primitives with Hanzo defaults and adds
JWT verification, the audit ledger, version CAS, and header hygiene. The root package
`kms` builds the whole surface as its own app — `kms.App(root) (*zip.App, error)` — so a
host composes it with `app.Use(kmsApp)` and no host type crosses into this module. The
standalone `cmd/kmsd` daemon composes the same app under a listener of its own. There is **no** Node fork, **no**
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

One caller, `.github/workflows/cicd.yml`, which uses
`hanzoai/ci/.github/workflows/build.yml@v2` with `mode: delegate` and the org's KMS
client pair. It reads `hanzo.yml`: the gate (`go test ./...`, the console's tests and
typecheck), the `kms` and `kms-fetch` images (built at the build door in-cluster;
deploying one is a universe pin), and the console site (`frontend/dist`, Sites slug
`kms`, main only, served at kms.hanzo.ai by universe `static-sites.yaml`).

GitHub is where it runs. The forge mirror of a hanzoai/* repo runs no workflows, so
the caller that sat under `.hanzo/workflows` from 6ba3f6d83c (2026-09-15) built
nothing: no gate, no image and no site publish for a month, with no red run to show
it. Check what is live by the served bundle:

```sh
B=$(curl -s https://kms.hanzo.ai/ | grep -oE '/assets/index-[A-Za-z0-9_-]+\.js')
curl -s "https://kms.hanzo.ai$B" | grep -c 'hanzo_kms_return'
```

## Console sign-in (`frontend/src/lib/session.ts`)

kms.hanzo.ai signs in on hanzo.ai, one way. Signed out, the console draws nothing and
leaves at once: the SDK mints its own request (`getLoginUrl`: client `hanzo-kms`,
redirect `https://kms.hanzo.ai/auth/callback`, an S256 challenge, no nonce; the verifier
stays on this origin) and the page is replaced by `https://hanzo.ai/login` + that query
(`kms.ts` `home`, `signinAddress`). hanzo.ai finishes it; `/auth/callback` redeems the
code on this origin's `/v1/iam` (the host routes `/v1` to cloud) and lands on the page
stashed under `hanzo_kms_return` (`back` keeps it on this origin). Sign-out is the SDK's
`end()` (revoke both tokens, end the session, all on this origin), then `/`, which
leaves for hanzo.ai again.

- Nothing calls or names hanzo.id: discovery is read from `https://api.hanzo.ai`, the
  token calls ride `proxyBaseUrl` = this origin, and `/v1/kms/config`'s `issuer` is used
  only by a brand with no `home` (it signs in at its own issuer). The CSP is universe
  `static-sites.yaml` `kms-headers`, `connect-src 'self' https://api.hanzo.ai`.
- Any hanzo-org account signs in; reading secrets takes an admin of the org or a grant
  there (`/v1/kms/secrets` 403 "takes an admin of the org or a grant there" otherwise).
  Measured 2026-10-16 with a throwaway.

## Entry points

```
cmd/kmsd/       production daemon (kms.App under a listener at kms.ListenAddr)
cmd/kms/        admin CLI
cmd/kms-fetch/  one-shot bootstrap fetch (see Dockerfile.kms-fetch)
cmd/smoke-zap/  ZAP transport smoke test
sdk/go/         kmsclient — Go client (HTTP + ZAP fallback) used by all services
sdk/go/node/    node identity protocol: statements, wire types, verification
frontend/       static TS dashboard (built in a separate Docker stage)
embed.go        root pkg: server assembly, routes, embedded frontend
auth.go jwks.go per-request JWT verify (RFC 7519) + JWKS cache
custody/        node identity keypairs held for nodes: seal, sign, rotate, revoke
docs/custody.tex  the spec the node daemon is written against
```

## Node identity custody (`custody/`) — spec: `docs/custody.tex`

A Hanzo node is named by a **wallet**: a secp256k1 keypair whose address is its
identity on the settlement L1, the account it stakes from and is paid to, and the
row the fleet view lists it under. The KMS generates that key, seals it, and
returns it to nobody — a node asks for signatures instead of holding a key.

`custody` is a **library**, not a surface. It holds keys and enforces what is a
property of a key; it derives no permission from a credential and never sees one.
The org-scoped HTTP plane and its authorization live in cloud (`apps/kms`), the
same place the secret plane moved to. `custody/mount_test.go` is the reference
mount, written out in full and exercised against the real client.

`(*Embedded).Custody()` (`custody.go`) is the one way to reach the store: it hands
out the store, never the database it lives in and never the master key, and
refuses when `KMS_MASTER_KEY_B64` is absent or malformed — a custody surface that
cannot seal must refuse rather than degrade.

- **Keyspaces are disjoint.** Record at `kms/nodes/{org}/{address}`, sealed key at
  `kms/custody/{org}/{address}`. Neither the secret keyspace nor an enumeration of
  node records can reach material; `node.Record` has no field for it.
- **The image binding is the cipher, not a check.** The key is sealed with
  `store.Seal` at `path="node"`, `name=address`, `env=measurement`, and unseal
  overwrites all three with what the CALLER presents. A wrong measurement is a GCM
  authentication failure. Seals under `KMS_MASTER_KEY_B64` (the record master),
  never the volume key.
- **Signing is a closed set.** `keccak256(H(tag) ‖ address ‖ measurement ‖ epoch ‖
  H(payload))` for attestation, and a succession tag for rotation. Fixed-length
  fields, so no digest here can be an RLP transaction hash: the wallet cannot be
  spent through this surface. Epochs must strictly increase per identity, and
  signatures are canonical (low-s), so one statement has one encoding.
- **The contract has one definition.** `sdk/go/node` holds the statements, wire
  types and verification — no store, transport or server dependency — and the KMS,
  hanzod and the chain indexer all import it; `custody` builds its digests by
  calling the same package a verifier does. Callers reach the surface through
  `sdk/go/kmsclient` (`Enroll`/`Sign`/`Rotate`/`Rebind`/`Revoke`/`Fleet`/`Node`)
  and refusals arrive as `*kmsclient.Failure` carrying the status.
- **Verify against what you expect.** `Receipt.Verify(payload)` takes the payload
  the caller holds rather than one the server echoed — a receipt carries the
  measurement it attests but never the payload. `Handover.Verify()` is
  self-contained. Paths carry no tenant: the server reads it from the credential.
- **TEE.** The measurement is `attestation.NodeAttestation.CpuTeeMeasurement`. With
  SEV-SNP/TDX it is a hardware launch measurement; on this fleet's hardware the node
  DECLARES it. Declared evidence records `attested: false` and still pins the key to
  one image. A claim of a hardware TEE with no linked verifier is REFUSED (400), not
  downgraded — recording "attested" on a claim would make the fleet view a lie.

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
