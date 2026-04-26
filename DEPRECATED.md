# DEPRECATED — Use luxfi/kms

`hanzoai/kms` is **deprecated**. The canonical Lux KMS implementation
lives at:

- **Code:** https://github.com/luxfi/kms
- **Image:** `ghcr.io/luxfi/kms:server-0d446b0` (latest from in-cluster build)
- **Go module:** `github.com/luxfi/kms`

This repo is archived as `kms-v1` for historical reference. The active
implementation is **Go-native, MPC-backed, ZapDB-storage** — replacing
the Infisical fork entirely.

## Migration

| Old | New |
|---|---|
| `ghcr.io/hanzoai/kms:*` | `ghcr.io/luxfi/kms:server` |
| `github.com/hanzoai/kms` (Go import) | `github.com/luxfi/kms` |
| `kms.hanzo.ai` (Infisical UI) | `api.kms.svc.cluster.local` (HTTP) |
| In-cluster KMS HTTP | `kms.lux-kms-go.svc.cluster.local` |
| In-cluster ZAP transport | `zap.kms.svc.cluster.local:9999` |

## Canonical Go client

```go
import "github.com/luxfi/kms"

// One line at process start:
func main() {
    kms.LoadEnv()                       // populates os.Setenv from KMS via ZAP
    db := os.Getenv("DATABASE_URL")
    run(db)
}

// Or programmatic:
v, err   := kms.Get(ctx, "DATABASE_URL")
all, err := kms.GetSecrets(ctx)
```

## Why

The Infisical fork (Node.js + PostgreSQL + Redis + complex web UI) was
incompatible with the "one and only one way" architectural principle.
The Go-native implementation:

- Pure Go binary, no Node.js / Postgres / Redis dependencies
- ZapDB embedded storage, age-encrypted S3 replication
- Native ZAP binary transport (port 9999) — no REST round-trip in-cluster
- MPC-backed envelope encryption via luxfi/mpc threshold signing
- KMSSecret CRD operator pulls secrets via ZAP into K8s Secrets

All KMSSecret CRDs across hanzo-k8s and lux-k8s already point at the
canonical Lux KMS as of 2026-04-26.
