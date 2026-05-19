# Verifying KMS Auth via IAM (Phase 6)

End-to-end verification that the trust chain
`user → IAM JWT → KMS RBAC` works in production. Run this after
Phases 1–5 (social-login configuration) ship and IAM is issuing tokens
from real-org applications.

The spec for what KMS enforces is in `docs/IAM_AUTH.md`. This runbook
exercises that spec against live KMS at `kms.hanzo.ai`.

## What we are proving

1. IAM can mint a JWT for a real-org user (not the admin bootstrap).
2. KMS accepts that JWT with the canonical claim shape.
3. Org scoping holds: the user's `owner` claim limits which
    KMS workspaces they can see.

## Prerequisites

- An IAM application registered with `enablePassword=true` and a known
   client_id (e.g. `hanzo-kms` — see `init_data.mainnet.json`).
- A real-org user with a known password (use the brand seed:
   `z@hanzo.ai` / `IloveHanzo2026!!!` per ~/.claude/CLAUDE.md global rule).
- `curl`, `jq`, and `openssl` on the verifying host.

## Step 1 — Mint a JWT via password grant

The canonical token endpoint is
`https://iam.hanzo.ai/v1/iam/oauth/access_token` (alias of
`/v1/iam/oauth/token`).

```bash
IAM=https://iam.hanzo.ai
APP_CLIENT_ID=hanzo-kms
APP_CLIENT_SECRET=<from-iam-admin-console>
USER=z@hanzo.ai
PASS='IloveHanzo2026!!!'

TOKEN=$(curl -sS -X POST "$IAM/v1/iam/oauth/access_token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=$APP_CLIENT_ID" \
  --data-urlencode "client_secret=$APP_CLIENT_SECRET" \
  --data-urlencode "username=$USER" \
  --data-urlencode "password=$PASS" \
  --data-urlencode "scope=openid profile email" \
  | jq -r .access_token)

test -n "$TOKEN" || { echo "JWT mint failed"; exit 1; }
echo "Token (first 60 chars): ${TOKEN:0:60}…"
```

Expected: a JWT string. Failure here = IAM-side problem (check IAM logs
for the OAuth handler, verify the user/password matches the seed).

## Step 2 — Sanity-check claims (no signature verify)

```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{
  iss, aud, sub, owner: .owner, exp: (.exp - now), roles: .roles
}'
```

Expected output:

```json
{
  "iss": "https://hanzo.id",
  "aud": [ "hanzo-kms" ],
  "sub": "<user-uuid>",
  "owner": "hanzo",
  "exp": 86399,
  "roles": [ … ]
}
```

Failure modes:

| Symptom | Cause |
|---|---|
| `iss` not `https://hanzo.id` | IAM is misconfigured (origin/jwtIss env) |
| `aud` missing client_id | Application's `tokenAudience` not set |
| `owner` empty | User row missing org assignment |
| `exp` already past | Clock skew on minting host |

## Step 3 — Hit a KMS endpoint with the JWT

The canonical "is this token good?" probe is `GET /v1/secrets/list`.
We avoid hitting an internal admin endpoint — we want to confirm the
JWT passes the RFC-7519 verification chain in `docs/IAM_AUTH.md`.

```bash
KMS=https://kms.hanzo.ai
WS=credentials  # the workspace the caller has access to via owner=hanzo

curl -sS -i -X GET "$KMS/v1/secrets/list?workspaceSlug=$WS&environment=prod&secretPath=/" \
  -H "Authorization: Bearer $TOKEN" \
  | head -30
```

Expected: HTTP 200 with `{"secrets":[...]}`. The list may be empty —
that's fine; we are checking the auth layer accepts the token, not the
particular secret content.

Failure interpretation:

| HTTP | Likely cause | Next action |
|---|---|---|
| 200 | success | done |
| 401 with `unauthorized` | JWT rejected (RFC 7519 check failed) | check Step 2 claims |
| 403 | JWT valid but org scope denies the workspace | confirm `owner` claim matches workspace tenant |
| 5xx | KMS internal error | check `kubectl logs deploy/kms` |

## Step 4 — Verify negative path (expired token)

To prove we're not just permissive, force an obviously-bad token:

```bash
curl -sS -i -X GET "$KMS/v1/secrets/list?workspaceSlug=$WS&environment=prod&secretPath=/" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Imdhcg.bogus.signature" \
  | head -5
```

Expected: `HTTP/2 401` with body `{"message":"unauthorized"}`. If you
get a 200 here, KMS is critically misconfigured — the JWT keyfunc is
not validating signatures.

## Step 5 — Org scope test (negative)

Mint a JWT for a user whose `owner` is `pars` (a different real org),
then attempt to list the `credentials` workspace (which is org-scoped
to hanzo):

```bash
PARS_USER=ops@pars.network
PARS_PASS='IlovePars2026!!!'
PARS_TOKEN=$(curl -sS -X POST "$IAM/v1/iam/oauth/access_token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=pars-kms" \
  --data-urlencode "client_secret=<pars-kms-secret>" \
  --data-urlencode "username=$PARS_USER" \
  --data-urlencode "password=$PARS_PASS" \
  | jq -r .access_token)

curl -sS -i -X GET "$KMS/v1/secrets/list?workspaceSlug=credentials&environment=prod&secretPath=/" \
  -H "Authorization: Bearer $PARS_TOKEN" \
  | head -5
```

Expected: `HTTP/2 403` (token is valid but RBAC denies).

If this returns 200, KMS is leaking secrets across orgs — escalate
immediately, do not deploy.

## Step 6 — JWKS rotation smoke test

KMS validates against IAM's JWKS endpoint
(`https://hanzo.id/v1/iam/.well-known/jwks`). After an IAM cert rotation,
KMS should pick up the new key within its cache TTL (default 10m).

```bash
# Confirm JWKS reachable and has the right keys
curl -sS "$IAM/v1/iam/.well-known/jwks" | jq '.keys[] | {kid, alg, kty}'
```

Expect at least one entry with `alg` in {RS256, RS384, RS512, ES256,
ES384, ES512, PS256, PS384, PS512, EdDSA} (per `docs/IAM_AUTH.md`).
`HS256`, `none`, or symmetric algorithms here is a P0 — file an issue
and pause rollout.

## Automating this in CI

Drop the above into a single shell script under
`~/work/hanzo/kms/e2e/iam-auth-smoke.sh` and run it in the post-deploy
smoke job. Exit non-zero on any unexpected status code. Mint a dedicated
`hanzo-kms-smoke` IAM app whose credentials live in KMS workspace
`credentials` at `/kms/smoke/` so the smoke script can self-bootstrap
from inside the cluster.

## Rotation cadence

- IAM signing cert: every 90 days (cert-manager handles).
- KMS JWKS cache: 10m TTL, no manual action.
- KMS service-to-service client_secret: every 12 months, rotate via
   Phase 2 runbook with workspace=`credentials`,
   path=`/kms/clients/<service>/`.
