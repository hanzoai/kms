# Hanzo KMS console

The app at kms.hanzo.ai. It signs in with Hanzo IAM and manages the signed-in
organization's secrets over the KMS API that cloud serves on the same host.

- Vite, React 19, TypeScript, Tailwind v4
- `@hanzo/iam/browser` for sign-in: authorization code with PKCE against the
  issuer `GET /v1/kms/config` names, as the `<brand>-kms` client
- `@tanstack/react-query` for fetch state, `wouter` for routes

## API it calls

| Method | Path | Page |
|--------|------|------|
| GET | `/v1/kms/config` | before sign-in |
| GET | `/v1/kms/health` | Status |
| GET | `/v1/kms/secrets?path=&env=` | Secrets |
| GET, DELETE | `/v1/kms/secrets/{path}/{name}?env=` | Secrets |
| POST | `/v1/kms/secrets` | Secrets |

The org is never in a URL: cloud reads it from the token.

## Commands

```bash
pnpm install
pnpm dev         # http://localhost:5173, proxies /v1 to a local cloud on :8000
pnpm test        # node:test over src/lib/kms.ts
pnpm build       # typecheck, then dist/
```

## Shipping

`hanzo.yml` declares the site: the forge runs `.hanzo/workflows/cicd.yml`,
which builds `dist/` and publishes it to the Sites plane as `kms`. The ingress
serves it on kms.hanzo.ai and sends `/v1` to cloud.
