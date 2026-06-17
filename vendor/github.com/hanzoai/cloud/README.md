# cloud

Unified Go control plane and binary for the Hanzo platform (HIP-0106).

[![Status](https://img.shields.io/badge/status-beta-blue)]()
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)]()

## Quick start

```bash
docker run -p 8080:8080 ghcr.io/hanzoai/cloud:latest
```

## What this is

`hanzoai/cloud` is one Go binary that mounts every Hanzo subsystem (iam, kms, base, gateway, ai, commerce, vfs, mq, dns, amqp, mcp, o11y, ...) into a single multi-tenant process. Same artifact serves `api.hanzo.ai`, `api.osage.cloud`, `api.lux.cloud`, `api.zoo.cloud`, and every white-label reseller. Brand, enabled subsystems, and tenant scope are deployment configuration.

## Specs

Implements:
- HIP-0014 Application Deployment
- HIP-0026 IAM
- HIP-0027 KMS
- HIP-0037 AI Cloud Platform
- HIP-0105 In-Process Extension Runtime
- HIP-0106 Unified Cloud Binary
- HIP-0302 Encrypted SQLite + ZapDB Durability

## Architecture

```
                 api.{tenant}.{brand}
                          |
                   hanzoai/cloud (one Go binary)
                          |
   +----------+----------+----------+----------+----------+
   |    iam   |   base   |   kms    |    ai    | gateway  | ...
   |  Mount() |  Mount() |  Mount() |  Mount() |  Mount() |
   +----------+----------+----------+----------+----------+
   per-tenant SQLite (HIP-0302)   |   Hanzo IAM JWKS (HIP-0026)
   replicate -> S3 (HIP-0107)     |   ZAP inter-subsystem RPC
```

Every subsystem exposes `func Mount(app *zip.App, deps cloud.Deps) error`. White-label fork pattern: customers fork this repo to launch their own ecosystem.


---

# Hanzo Cloud

The unified Go binary that imports every Hanzo-native subsystem and dispatches
requests per deployment configuration. One artifact, many subsystems.

Per [HIP-0106](https://github.com/hanzoai/HIPs/blob/main/HIPs/hip-0106-unified-hanzo-cloud-binary.md).

## Subsystems mounted

- `iam` — identity & access
- `base` — per-tenant SQLite + extension runtimes (per HIP-0105)
- `kms` — secrets
- `commerce` — checkout, billing, pricing, invoicing (light router; NOT in PCI-DSS scope)
- `ai` — LLM control plane / RAG / model hub / MCP management (was hanzoai/cloud pre-rename)
- `gateway` — HTTP routing + policy
- `o11y` — metrics / traces / logs
- `vfs` — virtual filesystem / object-store abstraction
- `mq` — message queue
- `dns`, `amqp`, `mcp`, `auto`, `tasks`, ... (full list per HIP-0106)

## Deployment modes

Same binary; different startup configuration:

```bash
cloud --enable=iam,base,kms,commerce,ai,gateway,o11y --brand=hanzo  --domain=hanzo.ai
cloud --enable=iam,base,kms,commerce,ai,gateway,o11y --brand=osage  --domain=osage.cloud
cloud --enable=iam,base,kms,commerce,ai,gateway,o11y --brand=lux    --domain=lux.cloud
cloud --enable=iam,base,kms,commerce,ai,gateway,o11y --brand=zoo    --domain=zoo.cloud
```

## White-label fork pattern

Customers fork `hanzoai/cloud` to launch their own ecosystem in one binary. Brand
detection, enabled subsystems, ZAP endpoints (payments / vault backends) are all
deployment configuration.

## Web framework

[hanzoai/zip](https://github.com/hanzoai/zip) — Sinatra-style Go web framework
built on Fiber v3. The ONE Go web framework. No `.Fast` escape hatch.

## Status

Scaffold. The Mount(app, deps) integration for each subsystem lands per
HIP-0106's migration phases.
