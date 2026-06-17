# Security Policy

## Reporting a vulnerability

Email security@hanzo.ai with details. Encrypt with our PGP key (fingerprint TBD).

We respond within 48 hours. Critical issues receive same-day acknowledgment.

## Scope

This policy covers code in this repository. For the broader Hanzo platform threat model, see [hanzoai/HIPs](https://github.com/hanzoai/HIPs).

## Sandbox boundary

`cloud` is the unified Hanzo Go binary that hosts multiple subsystems as in-process Go packages. Tenant isolation is enforced at the request boundary (JWT-validated `X-Org-Id`) and at the storage layer (per-tenant SQLite/ZapDB files with per-org KMS-derived DEKs); user-supplied extension code runs only inside the HIP-0105 in-process runtimes.

For runtime sandbox guarantees, see HIP-0105 (in-process extension runtimes).
