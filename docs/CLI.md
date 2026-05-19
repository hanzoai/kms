# Hanzo KMS — CLI Reference

The `kms` binary is the canonical administrative CLI for Hanzo KMS. One
source of truth: every operator tooling layer (Hanzo umbrella `hanzo`,
Liquidity `liquid secrets`, etc.) is a thin proxy that adds env-aware
base-URL resolution and delegates to the same REST surface this CLI
calls.

Wherever you see `kms <command>` here, the equivalent Liquidity-side
invocation is `liquid secrets <command>` (with `--env=dev|test|main`
resolving `kms.{env}.satschel.com` automatically).

## Install

```bash
# From source (Go 1.26+)
git clone https://github.com/hanzoai/kms ~/work/hanzo/kms
cd ~/work/hanzo/kms
go install ./cmd/kms
```

The binary lands at `$(go env GOPATH)/bin/kms`. Container builds use
`Dockerfile` at the repo root and ship under `ghcr.io/hanzoai/kms`.

## Authentication

Every operation requires a service-bound bearer token. The token
audience claim must match the calling service's identity (KMS
validates audience against the requested secret path).

```bash
export KMS_ADDR=https://kms.dev.satschel.com
export KMS_TOKEN=<bearer from kms.<env>.satschel.com login>
```

## Commands

### `kms health`

```bash
$ kms health
{"status":"ok","uptime":253401}
```

### `kms secret list [--prefix=<path>]`

List secrets under a path prefix.

```bash
$ kms secret list --prefix=liquid/usdl
liquid/usdl/treasury-key         v3   updated 3d ago
liquid/usdl/operator-key         v1   updated 18d ago
```

### `kms secret get <path>`

Fetch the cleartext value (subject to audience claim).

```bash
$ kms secret get liquid/usdl/treasury-key
0x4a8b2c...e9f1
```

### `kms secret set <path> <value> [--expected-version=N]`

Upsert. With `--expected-version`, server refuses concurrent overwrites
(CAS).

```bash
$ kms secret set liquid/usdl/treasury-key 0xnew...key --expected-version=3
ok (version=4)
```

### `kms secret delete <path>`

Remove a secret. No-op when absent.

### `kms encrypt --key=<id> <plaintext>`

Envelope-encrypt under the named key. Returns base64 ciphertext +
key version (for rotation tracking).

```bash
$ kms encrypt --key=liquid/age secret-payload
{"ciphertext":"...","keyVersion":2}
```

### `kms decrypt --key=<id> <ciphertext-b64>`

Reverse of `kms encrypt`.

### `kms version`

Print the binary version and exit.

## Environment variables

| Variable    | Default                  | Purpose                                    |
|-------------|--------------------------|--------------------------------------------|
| `KMS_ADDR`  | `http://localhost:8443`  | KMS server URL                             |
| `KMS_TOKEN` | (none)                   | Bearer used on every authenticated request |

## Related

- **REST surface**: `routers/` — every endpoint the CLI calls.
- **TypeScript SDK**: [`@hanzo/sdk/kms`](https://github.com/hanzo-js/sdk/tree/main/src/kms) — `KMSClient.secrets.fetch / set / list / remove` and `envelopes.encrypt / decrypt`.
- **Liquidity wrapper**: [`liquidityio/cli`](https://github.com/liquidityio/cli) — `liquid secrets …` adds env resolution.
- **Local dev**: `LOCAL_DEV.md`.

## Forbidden patterns

- ❌ Plaintext secrets in shell history. Use shell history file exclusion (HISTIGNORE) or use `kms secret set < <(echo $secret)`.
- ❌ Direct SQLite UPDATE on the KMS db. Bypasses audience validation; do not do this.
- ❌ Hand-rolled audience tokens. The bearer always comes from a real KMS login flow.
