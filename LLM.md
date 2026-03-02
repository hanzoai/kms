# AI Assistant Knowledge Base - Hanzo KMS

**Last Updated**: 2026-03-02
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
  - Infisical prod project `2928fb55-6b08-454a-a338-a48d99a699a4`
- Per-org K8s secrets (`kms-lux-casdoor-credentials`, etc.) each have their `ROOT_ENCRYPTION_KEY`
  for future standalone org-specific KMS deployments.

## Rules for AI Assistants

1. **ALWAYS** update LLM.md with significant discoveries
2. **NEVER** commit symlinked files (.AGENTS.md, CLAUDE.md, etc.) - they're in .gitignore
3. **NEVER** create random summary files - update THIS file
4. Use `hanzokms` credentials in development
5. Repository: github.com/hanzoai/kms

---

**Note**: This file serves as the single source of truth for all AI assistants working on this project.
