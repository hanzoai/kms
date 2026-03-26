# AI Assistant Knowledge Base - Hanzo KMS

**Last Updated**: 2026-03-25
**Project**: Hanzo KMS
**Organization**: Hanzo AI

## Project Overview

Hanzo KMS is an open-source Key Management Service for managing secrets, API keys, certificates, and encryption keys across infrastructure.

## Essential Commands

### Development
```bash
# Start local development environment
cp .env.dev.example .env
docker compose -f docker-compose.dev.yml up

# Run backend only
cd backend && npm run dev

# Run frontend only
cd frontend && npm run dev

# Run migrations
cd backend && npm run migration:latest
```

### Production
Production runs on **hanzo-k8s** DOKS cluster (`24.199.76.156`) at `kms.hanzo.ai`.
- Image: `hanzoai/kms:latest`
- DB: `postgres://hanzo:...@postgres.hanzo.svc:5432/kms`
- Redis: `redis-master:6379`

### Testing
```bash
# Backend unit tests
cd backend && npm run test:unit

# Backend e2e tests
cd backend && npm run test:e2e

# BDD tests
cd backend && npm run test:bdd
```

## Architecture

- **Backend**: Node.js/TypeScript with Fastify
- **Frontend**: React with Vite
- **Database**: PostgreSQL
- **Cache**: Redis
- **Containers**: Docker Compose

## Key Technologies

- TypeScript, Node.js, React
- PostgreSQL 14+, Redis
- Docker, Docker Compose
- Helm charts for Kubernetes deployment
- OpenTelemetry for observability

## Branding

- Package name: `@hanzo/kms`
- Docker image: `hanzoai/kms:latest`
- Database defaults: `hanzokms` (user, password, database)
- Network name: `hanzo-kms`
- Container prefixes: `hanzo-kms-*`
- Helm charts: `hanzo-kms-standalone`, `hanzo-kms-gateway`

## Development Workflow

1. Create feature branch from `main`
2. Make changes, run tests
3. Submit PR with description
4. CI checks must pass
5. Code review required
6. Squash and merge

## Context for All AI Assistants

This file (`LLM.md`) is symlinked as:
- `.AGENTS.md`
- `CLAUDE.md`
- `QWEN.md`
- `GEMINI.md`

All files reference the same knowledge base. Updates here propagate to all AI systems.

## Per-Org Root Encryption Key Isolation (2026-03-02)

Per-org key isolation was added to `kmsServiceFactory` so each tenant's KMS key material is
encrypted with a distinct root key rather than the shared `ROOT_ENCRYPTION_KEY`.

### How it works

- **`ORG_ENCRYPTION_KEYS`** env var: JSON map of org slug → base64-encoded 32-byte AES-256 key.
  Example: `{"hanzo":"<base64>","lux":"<base64>","pars":"<base64>","zoo":"<base64>"}`
- `getOrgRootKey(orgSlug)` helper inside the factory resolves the per-org key, falling back to
  `ROOT_ENCRYPTION_KEY` when no org-specific entry exists. This ensures ALL existing data
  (encrypted with the global key) continues to decrypt correctly.
- `findByIdWithAssociatedKms` in `kms-key-dal.ts` now selects `org.slug as orgSlug` via the
  existing Organization join, making it available to all internal KMS operations.
- `TGenerateKMSDTO` has `orgSlug?: string`. `getOrgKmsKeyId` passes `org.slug` when generating
  the default org KMS key.
- `encryptWithRootKey` / `decryptWithRootKey` remain on the global key — they are used for
  cross-org data (TOTP, secret sharing, teams, Slack).
- `importKeyMaterial` still uses `ROOT_ENCRYPTION_KEY` because its DTO has no `orgSlug`; update
  `TImportKeyMaterialDTO` if per-org isolation is needed there too.

### Files changed

- `backend/src/lib/config/env.ts` — added `ORG_ENCRYPTION_KEYS` field + `orgEncryptionKeys` parse
- `backend/src/db/migrations/utils/env-config.ts` — added `orgEncryptionKeys: {}` to migration env
- `backend/src/services/kms/kms-types.ts` — `orgSlug?: string` in `TGenerateKMSDTO`
- `backend/src/services/kms/kms-key-dal.ts` — `orgSlug` selected in `findByIdWithAssociatedKms`
- `backend/src/services/kms/kms-service.ts` — `getOrgRootKey` helper + 7 internal decrypt paths updated

### Multi-tenancy setup (live prod)

- KMS DB (`kms.hanzo.ai`): 4 orgs — `hanzo`, `lux`, `pars`, `zoo`
- `ORG_ENCRYPTION_KEYS` stored in:
  - K8s secret `kms-secrets` (namespace `hanzo`)
  - KMS prod project `2928fb55-6b08-454a-a338-a48d99a699a4`
- Per-org K8s secrets (`kms-lux-casdoor-credentials`, etc.) each have their `ROOT_ENCRYPTION_KEY`
  for future standalone org-specific KMS deployments.

## Vault-Ported Features (2026-03-11)

Eight major subsystems ported from HashiCorp Vault (MPL-2.0) to TypeScript.
29 files, ~3,400 lines total. All in `backend/src/services/` and `backend/src/lib/crypto/`.

### 1. Shamir Secret Sharing (`lib/crypto/shamir/`)
- **Source**: Vault `shamir/shamir.go`
- GF(2^8) Galois Field arithmetic (mult, div, inverse via Fermat's little theorem)
- `split(secret, parts, threshold)` → Buffer[] shares
- `combine(parts)` → Buffer original secret
- Fisher-Yates shuffle for random x-coordinates
- Zero external deps, pure Node.js crypto

### 2. Transit Engine - Encryption as a Service (`services/transit/`)
- **Source**: Vault `builtin/logical/transit/`
- Key types: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305, Ed25519, ECDSA-P256/P384, RSA-2048/3072/4096, HMAC
- Operations: encrypt, decrypt, **rewrap** (re-encrypt without plaintext exposure), sign, verify, HMAC, hash, data key generation, random bytes
- Key versioning with `hanzo:v{N}:{base64}` format
- HKDF-based key derivation with user context (convergent encryption support)
- Batch operations for all endpoints
- Auto-rotation via configurable period (min 1 hour)
- Export/import with `exportable` flag (one-way)

### 3. Lease Manager (`services/lease/`)
- **Source**: Vault `vault/expiration.go`
- TTL tracking with automatic revocation
- Exponential backoff retry (up to 6 attempts)
- Fair-share revocation queue (max 200 concurrent)
- Irrevocable lease tracking for failed revocations
- Event emission: issued, renewed, expired, revoked, revoke_failed

### 4. Seal/Unseal + Barrier (`services/seal/`)
- **Source**: Vault `vault/seal.go`, `vault/barrier_aes_gcm.go`
- AES-256-GCM encryption barrier with keyring (versioned key terms)
- Shamir seal: root key → split into N shares → T required to unseal
- Auto-unseal: root key encrypted by AWS KMS / GCP KMS
- Recovery key Shamir backup for KMS failure
- Key rotation via `barrier.rotate()` (new term, old keys for decrypt)
- Health check interval for KMS connectivity

### 5. ACL Policy Engine (`services/policy/`)
- **Source**: Vault `vault/policy.go`, `vault/acl.go`
- Capabilities: deny, create, read, update, delete, list, sudo, patch
- Path matching: exact, glob (`*`), segment wildcard (`+`)
- Template variables: `{{identity.org_id}}`, `{{identity.project_id}}`
- Deny takes absolute priority (longest-prefix match)
- LRU cache (1024 policies)
- Built-in `default` policy for self-service

### 6. Token System (`services/token/`)
- **Source**: Vault `vault/token_store.go`
- Token types: Service (`hkms_s.`), Batch (`hkms_b.`), Recovery (`hkms_r.`)
- HMAC-SHA256 signed for integrity
- Salted storage (never store raw token IDs)
- Parent-child hierarchy (revoking parent revokes children)
- Periodic tokens (renewable without TTL ceiling)
- Batch tokens (stateless, JWT-like, HMAC-verified)
- Num-uses tracking (decrement per use, revoke at 0)
- Accessor indirection (lookup metadata without token exposure)

### 7. Dynamic Secret Providers (`services/dynamic-secret/providers/`)
- **Source**: Vault `builtin/logical/database/`
- PostgreSQL/MySQL: temp users with `CREATE ROLE`, auto `DROP ROLE` on lease expiry
- Redis: ACL SETUSER/DELUSER for temporary access
- MongoDB: createUser/dropUser with role-based permissions
- SQL template variables: `{{name}}`, `{{password}}`, `{{expiration}}`
- Cryptographic password generation (configurable charset/length)
- Provider factory: `createProvider(config)` dispatches by type

### 8. TFHE-KMS Bridge (`services/tfhe/`)
- Bridges KMS key management with MPC TFHE subsystem (`luxfi/fhe v1.7.6`)
- Key types: TFHE_UINT{8,16,32,64,128,256}, TFHE_BOOL, TFHE_ADDRESS
- Operations: Add, Sub, Mul, Div, Lt/Gt/Lte/Gte/Eq/Ne, And/Or/Xor/Not, Select, Cast
- Threshold keygen via MPC cluster (NATS JetStream trigger)
- Threshold decryption (t-of-n shares via Lagrange interpolation)
- Private policy evaluation on encrypted transaction data
- Encrypted policy state: cumulative daily/monthly, last tx time, vesting
- T-Chain integration points (precompile at `0x0700...0080`)

### Integration Architecture

```
                    Hanzo KMS (TypeScript/Fastify)
                    ├── Secrets Store (PostgreSQL)
                    ├── External KMS (AWS, GCP)
                    ├── AI Access Control (per-secret policies)
                    ├── K8s Operator (KMSSecret CRDs)
                    │
  NEW ──────────────├── Transit Engine (EaaS)
  (Vault ports)     │   └── encrypt/decrypt/sign/verify/rewrap/datakey
                    ├── Seal Manager + Barrier
                    │   └── Shamir unseal / auto-unseal (AWS/GCP KMS)
                    ├── Lease Manager
                    │   └── TTL tracking, auto-revoke, retry queue
                    ├── ACL Policy Engine
                    │   └── path-based capabilities with templates
                    ├── Token System
                    │   └── HMAC-signed, salted, parent-child hierarchy
                    ├── Dynamic Secrets (PostgreSQL, Redis, MongoDB)
                    │   └── temp credentials with auto-revocation
                    └── TFHE Bridge
                        └── KMS ↔ MPC(luxfi/fhe) ↔ T-Chain
```

### HashiCorp Dependency Status

| Tool | Usage | Notes |
|------|-------|-------|
| Consul | In-use (MPC service discovery + wallet KV) | Keep |
| golang-lru | In-use (Lux node ZK proof cache) | Keep |
| Vault | **Ported** - 8 subsystems now native in KMS | Not needed as runtime dep |
| Terraform | Not used | Helm + Kustomize for deploys |
| Raft | Not needed | Lux Quasar (leaderless, post-quantum) |
| Serf/memberlist | Not needed | Lux P2P + mDNS + DHT |

## ZK-KMS Architecture (2026-03-25)

### Overview

The ZK-KMS is a distributed zero-knowledge key management system. No single node ever holds the
complete encryption key (CEK). The CEK is split via Shamir secret sharing across n MPC nodes, with
t-of-n threshold for reconstruction. Data is encrypted with AES-256-GCM, keys are wrapped with
HPKE (X25519 + HKDF-SHA256 + ChaCha20-Poly1305), and state is replicated via FHE CRDT sync across
all nodes.

### Components

```
mpc-node/                          # Go MPC node implementation
├── api/                           # gRPC + REST handlers
├── cmd/                           # Node binary entrypoint
├── compliance/                    # Regulatory compliance engine
│   ├── compliance.go              # Engine: modes (HIPAA/SEC/FINRA/SOX/GDPR), config, enforcement
│   ├── audit.go                   # WORM hash-chained audit log (SHA-256 chain, tamper detection)
│   ├── breakglass.go              # Emergency decryption tokens (HIPAA requirement)
│   ├── escrow.go                  # Regulator escrow shard management (HPKE-wrapped)
│   ├── retention.go               # Record retention policies (SEC 17a-4: 6yr, SOX: 7yr)
│   └── logging.go                 # Cloud logging sinks (webhook, GCP*, AWS*, Azure* via build tags)
├── crypto/                        # HPKE wrapping, key derivation
├── fhe/                           # FHE CRDT operations (luxfi/fhe v1.7.7)
├── node/                          # Node lifecycle, config
│   └── config.go                  # Config + EnterpriseConfig (multi-region, HSM, KMIP, audit sinks)
├── shard/                         # Shamir shard management, Lagrange interpolation
├── store/                         # ZapDB encrypted key-value store (luxfi/zapdb/v4)
└── deploy/                        # K8s deployment manifests

sdk/go/                            # Go client SDK
├── client.go                      # Set/Get/Delete/List, HPKE unlock/lock, CRDT sync
├── crypto.go                      # AES-256-GCM seal/open, HKDF key derivation
└── compliance_test.go             # Compliance integration tests
```

### Base Plugin

The KMS integrates with Hanzo Base via `base/plugins/kms/`:
- Transparent field-level encryption (AES-256-GCM) on configured collections
- FHE-encrypted HMAC-SHA256 indexes for equality queries on encrypted data
- REST API at `/api/kms/*` for secret CRUD, lock/unlock, invite, sync, status
- Record hooks: encrypt before write, decrypt after read (invisible to app layer)

### Compliance Module

The compliance engine wraps secret access with enforcement checks and immutable audit:
- **WORM Audit Log**: SHA-256 hash-chained entries, append-only, tamper-evident
- **Escrow Manager**: Regulator escrow shard (HPKE-wrapped), cooperative or unilateral reconstruction
- **Break-Glass**: Time-limited emergency decryption tokens (HIPAA), logged to audit trail
- **Retention Manager**: Prevents deletion of retained records per regulatory requirements
- **Cloud Logging Sinks**: Fan-out audit entries to external systems

### Cloud Logging Sinks

Audit entries can be replicated to external logging backends for enterprise compliance:
- **Always**: Local ZapDB (primary, handled by AuditLog)
- **Webhook**: POST JSON to any URL (always compiled)
- **GCP**: Cloud Logging + GCS with WORM retention lock (build tag `gcp`)
- **AWS**: CloudWatch Logs + S3 with Object Lock (build tag `aws`)
- **Azure**: Monitor + Blob with immutable storage (build tag `azure`)

Configured via `EnterpriseConfig.AuditSinks[]` in node config. The `SinkFanout` type writes to
all configured sinks with best-effort delivery and retry buffering.

### Enterprise Features (EnterpriseConfig)

| Feature | Config Field | Description |
|---------|-------------|-------------|
| Multi-region | `Regions`, `PrimaryRegion` | Geographic replication |
| Key rotation | `AutoRotateInterval`, `RotationNotifyDays` | Automatic CEK rotation policy |
| IP allow-list | `IPAllowList` | CIDR-based access restriction |
| MFA | `MFARequired` | Require MFA for secret access |
| Session timeout | `SessionTimeout` | Auto-lock CEK after inactivity |
| Audit sinks | `AuditSinks` | External log destinations |
| HSM | `HSMEnabled`, `HSMProvider`, `HSMSlotID` | cloudhsm, pkcs11, yubihsm |
| KMIP | `KMIPEnabled`, `KMIPEndpoint`, `KMIPCertFile` | Enterprise key lifecycle protocol |

### White-Label / Chain-Agnostic Design

The KMS is chain-agnostic. It connects via standard gRPC/REST API with no chain-specific configuration.
Any deployment — Lux L1/L2, exchange platforms, or web services — uses the same API and key material.

- Any chain can use KMS natively via the standard API
- No chain-specific configuration or special integration required
- Exchange platforms use KMS for: wallet keys, API keys, trading credentials, compliance records
- The compliance module handles ATS/BD/TA requirements natively for regulated platforms
- White-label deployments get full compliance, encryption, and audit features out of the box

## Rules for AI Assistants

1. **ALWAYS** update LLM.md with significant discoveries
2. **NEVER** commit symlinked files (.AGENTS.md, CLAUDE.md, etc.) - they're in .gitignore
3. **NEVER** create random summary files - update THIS file
4. Use `hanzokms` credentials in development
5. Repository: github.com/hanzoai/kms

---

**Note**: This file serves as the single source of truth for all AI assistants working on this project.
