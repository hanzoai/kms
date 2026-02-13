# AI Assistant Knowledge Base - KMS

**Last Updated**: 2026-01-26
**Project**: KMS
**Organization**: Hanzo AI

## Project Overview

KMS is an open-source Key Management Service for managing secrets, API keys, certificates, and encryption keys across infrastructure. It is a fork of [Infisical](https://github.com/Infisical/infisical).

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
- Image: `infisical/infisical:latest` (upstream)
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

This fork has been rebranded from Infisical:
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

## Rules for AI Assistants

1. **ALWAYS** update LLM.md with significant discoveries
2. **NEVER** commit symlinked files (.AGENTS.md, CLAUDE.md, etc.) - they're in .gitignore
3. **NEVER** create random summary files - update THIS file
4. Preserve fork attribution to Infisical in relevant contexts
5. Use `hanzokms` credentials in development, not `infisical`

---

**Note**: This file serves as the single source of truth for all AI assistants working on this project.
