# Security Policy

## Reporting a vulnerability

Email security@hanzo.ai with details. Encrypt with our PGP key (fingerprint TBD).

We respond within 48 hours. Critical issues receive same-day acknowledgment.

## Scope

This policy covers code in this repository. For the broader Hanzo platform threat model, see [hanzoai/HIPs](https://github.com/hanzoai/HIPs).

## Sandbox boundary

`kms` is the root of trust for every secret in the Hanzo platform and is treated as such — master keys are sealed, all access is policy-gated and audited, and AI agents are subject to per-secret approval policies (auto-approve, requires-approval, blocked). Tenants are isolated by per-org namespace; cross-namespace access is impossible without an explicit cross-org grant.

For runtime sandbox guarantees, see HIP-0105 (in-process extension runtimes).
