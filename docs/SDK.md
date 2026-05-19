# Hanzo KMS — SDK Reference

The canonical client library for Hanzo KMS is
[`@hanzo/sdk/kms`](https://github.com/hanzo-js/sdk) — the TypeScript
sub-client inside the unified Hanzo SDK. Every KMS operation supported
by the CLI ([CLI.md](CLI.md)) is also available programmatically here.

## Install

```bash
npm install @hanzo/sdk
```

## Quick start

```ts
import { KMSClient } from '@hanzo/sdk/kms'

const kms = new KMSClient({
  baseUrl: 'https://kms.dev.satschel.com',
  token: process.env.KMS_TOKEN,
})

// List secrets under a prefix
const list = await kms.secrets.list('liquid/usdl')

// Fetch one
const sec = await kms.secrets.fetch('liquid/usdl/treasury-key')

// Upsert (CAS via expectedVersion)
await kms.secrets.set('liquid/usdl/treasury-key', '0xnew...key', {
  expectedVersion: sec.version,
})

// Envelope encryption
const { ciphertext } = await kms.envelopes.encrypt('liquid/age', 'plaintext')
const { plaintext } = await kms.envelopes.decrypt('liquid/age', ciphertext)
```

## API surface

| TS surface                                                    | REST endpoint                          | CLI equivalent                                  |
|---------------------------------------------------------------|----------------------------------------|-------------------------------------------------|
| `kms.secrets.list(prefix)`                                    | `GET /v1/kms/secrets?prefix=…`         | `kms secret list --prefix=…`                    |
| `kms.secrets.fetch(path)`                                     | `GET /v1/kms/secrets/<path>`           | `kms secret get <path>`                         |
| `kms.secrets.set(path, value, { metadata, expectedVersion })` | `PUT /v1/kms/secrets/<path>`           | `kms secret set <path> <value> [--expected-version=N]` |
| `kms.secrets.remove(path)`                                    | `DELETE /v1/kms/secrets/<path>`        | `kms secret delete <path>`                      |
| `kms.envelopes.encrypt(keyId, plaintext)`                     | `POST /v1/kms/encrypt`                 | `kms encrypt --key=<id> <plaintext>`            |
| `kms.envelopes.decrypt(keyId, ciphertext)`                    | `POST /v1/kms/decrypt`                 | `kms decrypt --key=<id> <ciphertext-b64>`       |
| `kms.health()`                                                | `GET /healthz`                         | `kms health`                                    |

## Error handling

```ts
import { HanzoAPIError } from '@hanzo/sdk'

try {
  await kms.secrets.fetch('does/not/exist')
} catch (err) {
  if (err instanceof HanzoAPIError && err.status === 404) {
    // expected
  } else {
    throw err
  }
}
```

CAS failures (concurrent write conflict) come back as `HanzoAPIError(409)`
with body `{ error: "version_conflict", currentVersion: N }`.

## See also

- [`CLI.md`](CLI.md) — equivalent `kms` CLI binary
- [`@hanzo/sdk` README](https://github.com/hanzo-js/sdk) — umbrella SDK covering IAM, Commerce, Billing, MPC, PaaS, Team
- [`liquidityio/cli`](https://github.com/liquidityio/cli) — env-aware `liquid secrets …` wrapper
