# Zero-Knowledge + FHE Architecture for Hanzo KMS

**Status**: Architecture Decision Record
**Date**: 2026-03-25
**Author**: CTO

## Problem Statement

Hanzo KMS currently stores encrypted secrets server-side with per-org root keys
(`ORG_ENCRYPTION_KEYS`) held by the server. The server can decrypt any org's
data. This is defense-in-depth but not zero-knowledge: a compromised server or
rogue operator can read all secrets.

**Goal**: Transform KMS so the server provably never possesses plaintext secrets.
Each org's secrets are encrypted with a master key that is Shamir-split across
distributed MPC nodes. The nodes evaluate policies via TFHE on encrypted data,
sync state via encrypted CRDTs, and never require a central coordinator or
shared database.

**Constraints**:
- Must be backward-compatible with existing KMS API consumers during migration
- Must use `luxfi/fhe`, `luxfi/lattice`, `luxfi/crypto`, `luxfi/threshold`, `luxfi/mpc` -- no external FHE libs
- Go packages stay at v1.x.x (note: lattice is at v7, fhe at v1.7.x -- lattice is the exception already in production)
- Client SDK must work in browser (WASM), Node.js, Go, and CLI
- KMS backend is TypeScript/Fastify -- MPC nodes are Go, run as independent distributed processes (NOT sidecars)
- No centralized database. Each MPC node has its own embedded ZapDB instance.
- Secrets in KMS, never in env files, never in git

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│ Client (SDK / CLI / Browser)                                     │
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  @hanzo/kms-sdk  │  │  hanzo kms CLI  │  │  WASM (browser) │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
│           │                    │                     │           │
│  ┌────────▼────────────────────▼─────────────────────▼────────┐  │
│  │  ZK Client Core                                            │  │
│  │  - Derive CEK from admin credentials (Argon2id)            │  │
│  │  - AES-256-GCM encrypt/decrypt secret payloads             │  │
│  │  - Wrap CEK for member sharing (HPKE: ML-KEM-768+X25519)   │  │
│  │  - Generate FHE evaluation key for MPC nodes               │  │
│  │  - Produce encrypted metadata (FHE) for distributed eval   │  │
│  └────────────────────────────┬───────────────────────────────┘  │
│                               │                                  │
│  All data leaving the client is encrypted. CEK never leaves.     │
└───────────────────────────────┼──────────────────────────────────┘
                                │ HTTPS (encrypted blobs + FHE ciphertexts)
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│ KMS API Server (zero-knowledge mode, TypeScript/Fastify)         │
│                                                                  │
│  - Receives encrypted blobs from clients                         │
│  - Routes to MPC node cluster for storage and evaluation         │
│  - Returns encrypted results to clients                          │
│  - Cleartext audit log (who, when, what action, which secret ID) │
│  - No secret values. No CEK. No master key.                      │
│                                                                  │
│  API ──── gRPC ────▼                                             │
└────────────────────┼─────────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────────┐
│ Distributed MPC Node Cluster (Go)                                │
│                                                                  │
│  No central coordinator. No shared database.                     │
│  Shamir t-of-n reconstruction only when needed.                  │
│  TFHE enables policy evaluation without any node seeing all      │
│  shards.                                                         │
│                                                                  │
│  ┌──────────────────────┐  ┌──────────────────────┐              │
│  │ MPC Node 1           │  │ MPC Node 2           │              │
│  │ ┌──────────────────┐ │  │ ┌──────────────────┐ │              │
│  │ │ ZapDB (local)    │ │  │ │ ZapDB (local)    │ │              │
│  │ │ encrypted at rest│ │  │ │ encrypted at rest│ │              │
│  │ └──────────────────┘ │  │ └──────────────────┘ │              │
│  │ ┌──────────────────┐ │  │ ┌──────────────────┐ │              │
│  │ │ Threshold Shard  │ │  │ │ Threshold Shard  │ │    FHE CRDT  │
│  │ │ (Shamir share)   │◄├──┼─┤ (Shamir share)   │ │◄───sync────► │
│  │ └──────────────────┘ │  │ └──────────────────┘ │              │
│  │ ┌──────────────────┐ │  │ ┌──────────────────┐ │              │
│  │ │ FHE Evaluator    │ │  │ │ FHE Evaluator    │ │              │
│  │ │ (TFHE gates)     │ │  │ │ (TFHE gates)     │ │              │
│  │ └──────────────────┘ │  │ └──────────────────┘ │              │
│  └──────────────────────┘  └──────────────────────┘              │
│                                                                  │
│  ┌──────────────────────┐  ┌──────────────────────┐              │
│  │ MPC Node 3           │  │ MPC Node N           │              │
│  │ ┌──────────────────┐ │  │ ┌──────────────────┐ │              │
│  │ │ ZapDB (local)    │ │  │ │ ZapDB (local)    │ │              │
│  │ │ encrypted at rest│ │  │ │ encrypted at rest│ │              │
│  │ └──────────────────┘ │  │ └──────────────────┘ │              │
│  │ ┌──────────────────┐ │  │ ┌──────────────────┐ │              │
│  │ │ Threshold Shard  │ │  │ │ Threshold Shard  │ │              │
│  │ │ (Shamir share)   │ │  │ │ (Shamir share)   │ │              │
│  │ └──────────────────┘ │  │ └──────────────────┘ │              │
│  │ ┌──────────────────┐ │  │ ┌──────────────────┐ │              │
│  │ │ FHE Evaluator    │ │  │ │ FHE Evaluator    │ │              │
│  │ │ (TFHE gates)     │ │  │ │ (TFHE gates)     │ │              │
│  │ └──────────────────┘ │  │ └──────────────────┘ │              │
│  └──────────────────────┘  └──────────────────────┘              │
│                                                                  │
│  Encrypted CRDT sync (luxfi/fhe CRDT) between all nodes.         │
│  LWW-Register with FHE-encrypted timestamps.                     │
│  Convergence guaranteed by CRDT + FHE correctness.               │
└──────────────────────────────────────────────────────────────────┘
```

## Decision: No Centralized Database

The prior version used PostgreSQL. Rejected.

**Rationale**:
- A shared PostgreSQL re-centralizes the threat model: a compromised DB means all encrypted blobs are in one place for offline attack
- TFHE is inherently distributed -- sharding keys and evaluating gates across independent nodes is the native model
- ZapDB (luxfi/zapdb) is an embedded, pure-Go BadgerDB fork with SSI transactions and encryption at rest -- each MPC node gets its own isolated instance with no shared state
- CRDT sync between nodes (using luxfi/fhe encrypted CRDT) provides eventual consistency without a coordinator
- No external database process to manage, no connection strings, no network-accessible DB attack surface

**Decision**: Each MPC node stores its data in a local ZapDB instance, encrypted at rest with the node's own key. Nodes sync encrypted state via FHE CRDT. The KMS API server is stateless (except the cleartext audit log, which can use any append-only store).

## Key Hierarchy

```
Org Admin Passphrase
  │
  ▼
Argon2id(passphrase, org_id || "hanzo-kms-cek-v1", {m=256MiB, t=4, p=2})
  │
  ▼
Master Key (256-bit)
  │
  ├── Shamir split → n shards distributed to MPC nodes
  │     Each shard encrypted with its node's ZapDB encryption key
  │     t-of-n reconstruction only for:
  │       • CEK derivation (HKDF)
  │       • Key rotation ceremony
  │       • Member invitation
  │
  ├── HKDF-SHA256(master, salt=org_id, info="cek-aes256gcm") → CEK
  │     Used to encrypt/decrypt all secret payloads for this org.
  │     Never leaves the client.
  │
  ├── HKDF-SHA256(master, salt=org_id, info="wrapping-hpke") → Wrapping Seed
  │     Deterministic HPKE keypair (ML-KEM-768+X25519 hybrid) for
  │     wrapping CEK to new members.
  │
  └── FHE evaluation keys derived separately (no reconstruction needed)
        Each MPC node derives its own FHE eval key from its shard.
        Nodes can evaluate TFHE gates independently.
        No node ever sees the full master key during FHE evaluation.
```

### Configurable Shamir Threshold

Per-org configurable t-of-n using `luxfi/threshold` + `luxfi/mpc`:

| Org Tier | Threshold | Rationale |
|----------|-----------|-----------|
| Small org | 2-of-3 | Minimum viable fault tolerance, low ceremony overhead |
| Enterprise | 3-of-5 or 5-of-7 | Tolerate 2 node failures, standard enterprise SLA |
| Critical | 7-of-11 | High-assurance environments, government/financial |

Threshold is set during org bootstrap (`zk init --threshold 3 --nodes 5`) and
can be re-keyed via a key rotation ceremony. The MPC ceremony protocol uses
`luxfi/mpc` for distributed key generation and `luxfi/threshold` for threshold
signature operations during reconstruction.

### Why HPKE Instead of Raw X25519

X25519 raw Diffie-Hellman requires manual AEAD wrapping, nonce management, and
offers no post-quantum path. `luxfi/crypto/encryption` already implements
HPKE (RFC 9180) with hybrid ML-KEM-768+X25519. One wrapping mechanism,
post-quantum ready from day one, already in our stack.

## Key Ceremony Flows

### 1. Org Creation (Bootstrap)

```
Client:
  1. Admin enters org name + passphrase + threshold config (t, n)
  2. org_id = deterministic UUID from org slug (already exists in IAM)
  3. master_key = Argon2id(passphrase, org_id || "hanzo-kms-cek-v1")
  4. cek = HKDF-SHA256(master_key, org_id, "cek-aes256gcm")
  5. wrapping_kp = HPKE keypair from HKDF(master_key, org_id, "wrapping-hpke")
  6. shards = Shamir.Split(master_key, n, t) via luxfi/crypto
  7. For each MPC node i:
       encrypted_shard_i = HPKE.Seal(node_i_pubkey, shard_i)
  8. POST /v1/orgs/:org/zk/init
       Body: {
         wrapping_public_key: <bytes>,
         threshold: t,
         node_count: n,
         encrypted_shards: [<shard_1>, ..., <shard_n>],
         recovery_verification_hash: SHA-256(master_key),
       }

KMS API Server:
  1. Distribute encrypted_shard_i to MPC node i
  2. Store wrapping_public_key (for member invitations)
  3. Store recovery_verification_hash (to verify recovery ceremonies)
  4. Mark org as zk_enabled = true, threshold = t, nodes = n

MPC Nodes (each independently):
  1. Receive encrypted shard
  2. Decrypt with node's private key
  3. Store shard in local ZapDB (encrypted at rest by ZapDB)
  4. Derive per-org FHE eval key from shard
  5. Node never sees master_key or any other shard
```

### 2. Member Invitation

```
Admin Client:
  1. Retrieve invitee's HPKE public key (from IAM profile or out-of-band)
  2. wrapped_cek = HPKE.Seal(invitee_pubkey, info="hanzo-kms-cek", cek)
  3. POST /v1/orgs/:org/zk/members
       Body: {
         member_id: <iam_user_id>,
         wrapped_cek: <bytes>,
         wrapped_by: <admin_user_id>,
       }

KMS API Server:
  1. Replicate wrapped_cek blob to MPC nodes via CRDT
  2. Only the invitee's private key can unwrap it

Invitee Client:
  1. GET /v1/orgs/:org/zk/members/me/wrapped-cek
  2. cek = HPKE.Open(my_private_key, info="hanzo-kms-cek", wrapped_cek)
  3. Cache CEK in memory (encrypted at rest on client device)
```

### 3. CEK Rotation

```
Admin Client:
  1. Initiate MPC ceremony: t-of-n nodes reconstruct master_key
  2. Generate new CEK: cek_v2 = HKDF(master_key, org_id, "cek-aes256gcm-v2")
  3. GET /v1/orgs/:org/zk/secrets (returns encrypted blobs)
  4. For each secret:
       plaintext = AES-256-GCM.Decrypt(cek_v1, blob)
       new_blob = AES-256-GCM.Encrypt(cek_v2, plaintext)
  5. PUT /v1/orgs/:org/zk/rotate
       Body: {
         new_blobs: [{secret_id, encrypted_payload}...],
         new_wrapping_pubkey: <if wrapping key also rotated>,
         version: 2,
       }
  6. Re-wrap cek_v2 for all members:
       For each member:
         wrapped = HPKE.Seal(member_pubkey, info="hanzo-kms-cek", cek_v2)
         PUT /v1/orgs/:org/zk/members/:id/wrapped-cek
  7. Optionally re-shard master_key with new threshold params

MPC Nodes:
  1. CRDT-sync new encrypted blobs across all nodes
  2. Old blobs retained in ZapDB history (still encrypted with cek_v1)
  3. New FHE eval keys derived if shards changed
  4. No node sees plaintext at any point
```

### 4. Recovery (Admin Passphrase Lost)

```
Recovery Ceremony:
  1. t of n Shamir share holders provide their shares
     (MPC nodes release shards via authenticated ceremony, luxfi/mpc protocol)
  2. master_key = Shamir.Combine(shares)
  3. Verify: SHA-256(master_key) == stored recovery_verification_hash
  4. Derive CEK from master_key (same HKDF path)
  5. New admin sets new passphrase → new master_key_v2
  6. Re-derive all keys, re-wrap CEK for all members
  7. Re-shard master_key_v2 to MPC nodes
  8. Full rotation ceremony (step 3 above)
```

## FHE Integration Points

### Distributed FHE Evaluation

TFHE is inherently distributed. Each MPC node runs its own FHE evaluator with
its own eval key derived from its shard. Policy evaluation happens across
nodes without any single node possessing the full decryption capability.

### What Runs on Encrypted Data

The MPC nodes evaluate policies on **encrypted metadata**, not on the
secrets themselves. The secrets are AES-256-GCM encrypted with the CEK. The FHE
layer operates on structured metadata that the client encrypts with TFHE before
uploading.

| Operation | FHE Scheme | Input | Output | Purpose |
|-----------|-----------|-------|--------|---------|
| Rotation due | TFHE | Encrypted(last_rotated_ts), Encrypted(policy_max_age) | Encrypted(bool) | Trigger rotation reminder without knowing when secret was last rotated |
| Expiry check | TFHE | Encrypted(expiry_ts), Encrypted(now_ts) | Encrypted(bool) | Detect expired secrets without knowing expiry dates |
| Access count | TFHE | Encrypted(count), Encrypted(max_count) | Encrypted(bool) | Rate limiting without knowing actual counts |
| Policy AND/OR | TFHE | Encrypted(bool), Encrypted(bool) | Encrypted(bool) | Combine policy results |

### What Does NOT Use FHE

- **Secret encryption/decryption**: AES-256-GCM with CEK. Standard symmetric crypto. FHE is too slow for bulk data.
- **Member key wrapping**: HPKE. Standard asymmetric crypto.
- **Authentication**: OIDC JWT from IAM. No change.
- **Audit logging**: Cleartext metadata (who, when, what action, which secret ID). No secret values in audit logs.

### FHE Metadata Lifecycle

```
Client:
  1. When creating/updating a secret, also create FHE metadata:
     encrypted_expiry = TFHE.Encrypt(eval_key, expiry_timestamp)
     encrypted_access_count = TFHE.Encrypt(eval_key, 0)
     encrypted_rotation_ts = TFHE.Encrypt(eval_key, now())
  2. Upload alongside the AES-encrypted secret payload

MPC Nodes (periodic distributed policy evaluation):
  1. Each node loads FHE metadata from its local ZapDB
  2. Each node evaluates TFHE gates with its local eval key:
     expired = TFHE.IntGreaterThan(eval_key, encrypted_now, encrypted_expiry)
     needs_rotation = TFHE.IntGreaterThan(eval_key, encrypted_age, encrypted_max_age)
  3. Results are encrypted booleans
  4. CRDT-sync evaluation results across nodes (FHE-encrypted merge)
  5. Client fetches and decrypts results to see which secrets need attention
```

### CRDT Sync Between Nodes

Nodes sync encrypted state using `luxfi/fhe` CRDT:

- **Data structure**: LWW-Register (Last-Writer-Wins) with FHE-encrypted timestamps
- **Merge semantics**: Encrypted timestamp comparison via TFHE gates -- no node needs to see plaintext timestamps to determine ordering
- **Convergence**: Guaranteed by CRDT algebra + FHE correctness (see formal proofs below)
- **Transport**: Gossip protocol between MPC nodes, encrypted payloads only
- **Conflict resolution**: Deterministic -- LWW with FHE comparison produces identical merge result on all nodes

### Why TFHE (Not BFV/BGV/CKKS)

TFHE (from `luxfi/fhe`) is the right choice because:
- We need boolean comparisons (is expired? needs rotation?), not arithmetic on vectors
- TFHE gate evaluation is ~10ms, fast enough for metadata checks
- TFHE is natively distributable across MPC nodes
- CKKS is for approximate arithmetic on vectors (ML inference) -- wrong tool
- BFV/BGV would work but add complexity for no gain over TFHE booleans

**Decision**: TFHE for all FHE metadata operations. `luxfi/lattice` is the underlying
math library (already a dependency of `luxfi/fhe`). We use lattice indirectly, not directly.

## Formal Security Proofs

### 1. Zero-Knowledge Property

**Theorem**: The KMS server and MPC nodes never possess plaintext secrets.

**Proof sketch** (reduction to AES-256-GCM IND-CPA):

Assume an adversary A who compromises the server and all MPC nodes can distinguish
encrypted secret payloads from random bytes. Construct adversary B against
AES-256-GCM IND-CPA:

1. B receives an AES-256-GCM oracle from the IND-CPA challenger.
2. B simulates the KMS environment for A, using the oracle to produce ciphertexts.
3. When A distinguishes a ciphertext, B uses A's answer to break the IND-CPA game.

Since AES-256-GCM is IND-CPA secure under standard assumptions, A cannot exist.
Therefore the server learns nothing about secret values from stored blobs.

The CEK (Content Encryption Key) is derived via Argon2id + HKDF on the client.
Neither the server nor any MPC node ever receives the CEK. The server stores only
HPKE-wrapped CEK copies that require each member's private key to unwrap.

### 2. Threshold Security

**Theorem**: Any coalition of fewer than t nodes learns nothing about the master key.

**Proof** (information-theoretic, Shamir's Secret Sharing):

Shamir's scheme over GF(2^256) encodes the master key as the constant term of a
random polynomial of degree t-1. Any subset of t-1 or fewer shares is statistically
independent of the secret:

```
For any master key m and any set S of t-1 shares:
  Pr[master_key = m | shares = S] = Pr[master_key = m]
```

This is information-theoretic -- not computational. No amount of computing power
helps an adversary holding t-1 shares. This holds regardless of:
- The adversary's computational resources (including quantum computers)
- The values of the shares held
- Side-channel information from FHE evaluation (eval keys are derived independently)

The threshold is configurable per-org (2-of-3, 3-of-5, 5-of-7, 7-of-11). The
security margin scales linearly: an adversary must compromise t nodes, not just one.

### 3. FHE Correctness

**Theorem**: Homomorphic evaluation on TFHE ciphertexts produces correct results.

**Proof sketch** (TFHE bootstrapping correctness):

TFHE (Torus FHE) represents bits as elements of the real torus T = R/Z with
Gaussian noise. Each gate evaluation:

1. Computes a noisy result via the homomorphic operation
2. Applies programmable bootstrapping to reduce noise to a fresh level

The bootstrapping procedure maps a noisy ciphertext c back to a fresh ciphertext
c' encrypting the same plaintext bit, provided the input noise is below the
bootstrapping threshold:

```
If |noise(c)| < q/4, then Decrypt(Bootstrap(c)) = Decrypt(c)
```

For our policy evaluation (integer comparison, boolean AND/OR), the circuit depth
is bounded (< 64 gates for timestamp comparison). The noise growth per gate is
controlled by the bootstrapping key parameters chosen in `luxfi/fhe`. With
standard security parameters (n=1024, sigma=3.2), the probability of correctness
failure is < 2^{-128} per gate evaluation.

### 4. CRDT Convergence

**Theorem**: Encrypted CRDT merge converges across all MPC nodes.

**Proof** (reduction to FHE correctness + LWW-Register convergence):

Step 1: Standard LWW-Register convergence.
For plaintext LWW-Registers with a total order on timestamps:
- merge(a, b) = max(a.timestamp, b.timestamp) selects the latest write
- merge is commutative, associative, and idempotent (CRDT axioms)
- Therefore all nodes converge to the same state regardless of message ordering

Step 2: FHE-encrypted LWW-Register preserves convergence.
Our CRDT stores FHE-encrypted timestamps. The merge operation uses TFHE
homomorphic comparison:

```
merge(a, b) = TFHE.Mux(
    TFHE.IntGreaterThan(a.enc_timestamp, b.enc_timestamp),
    a,  // if a is newer
    b   // if b is newer
)
```

By FHE Correctness (Theorem 3), `TFHE.IntGreaterThan` on encrypted timestamps
produces the same boolean result as comparison on plaintext timestamps. Therefore
`TFHE.Mux` selects the same register value as plaintext `max()`.

Since the encrypted merge is functionally equivalent to plaintext merge, and
plaintext LWW-Register converges, the encrypted CRDT converges.

### 5. Post-Quantum Resistance

**Theorem**: Key exchange survives a quantum adversary.

**Proof sketch** (ML-KEM-768 IND-CCA2 security):

CEK wrapping uses HPKE with hybrid ML-KEM-768+X25519 (via `luxfi/crypto/encryption`):

1. ML-KEM-768 (NIST FIPS 203) is based on the Module-LWE problem with
   parameters (k=3, n=256, q=3329). The best known quantum attack (Grover +
   lattice sieving) requires > 2^{143} quantum gates.

2. The hybrid construction (ML-KEM-768 + X25519) provides IND-CCA2 security
   if **either** primitive is secure:
   ```
   Security(Hybrid) >= max(Security(ML-KEM-768), Security(X25519))
   ```

3. TFHE itself is lattice-based (Ring-LWE). Its security against quantum
   adversaries is equivalent to ML-KEM at the same parameter level. Our TFHE
   parameters (n=1024) provide > 128 bits of post-quantum security.

4. Argon2id key derivation is symmetric (no public-key component). Quantum
   adversaries gain at most a Grover speedup (sqrt), reducing 256-bit security
   to 128-bit. This remains secure.

Therefore all cryptographic operations in the system maintain >= 128-bit security
against quantum adversaries.

## File Structure

```
backend/src/
├── services/
│   └── zk/                           # ZK-KMS service module
│       ├── index.ts                  # Service barrel export
│       ├── zk-service.ts             # Core ZK service (blob CRUD, member mgmt)
│       ├── zk-types.ts               # TypeScript types for ZK operations
│       ├── zk-router.ts              # Fastify routes (/v1/orgs/:org/zk/*)
│       ├── zk-mpc-client.ts          # gRPC client to MPC node cluster
│       └── zk-migration.ts           # Migration helpers (legacy → ZK mode)
│
├── lib/crypto/
│   ├── hpke/                         # HPKE wrapping (thin layer over Web Crypto / Node crypto)
│   │   ├── index.ts
│   │   └── hpke.ts                   # HPKE Seal/Open for CEK wrapping
│   └── shamir/                       # Shamir secret sharing (already ported)
│       ├── index.ts
│       └── shamir.ts
│
└── audit/
    └── audit-log.ts                  # Append-only cleartext audit log (no secret values)

sdk/                                  # Client SDK package
├── package.json                      # @hanzo/kms-zk-sdk
├── src/
│   ├── index.ts                      # Public API
│   ├── key-derivation.ts             # Argon2id + HKDF key derivation
│   ├── cek.ts                        # CEK encrypt/decrypt (AES-256-GCM)
│   ├── wrapping.ts                   # HPKE CEK wrapping for members
│   ├── fhe-metadata.ts              # TFHE metadata encryption (via @luxfhe/wasm)
│   ├── recovery.ts                   # Shamir share generation/combination
│   ├── client.ts                     # HTTP client for KMS ZK endpoints
│   └── types.ts                      # Shared types
└── wasm/                             # WASM build of TFHE for browser
    └── (pulled from @luxfhe/wasm)

cli/
├── commands/
│   └── zk/                           # CLI subcommands
│       ├── init.ts                   # hanzo kms zk init --threshold t --nodes n
│       ├── invite.ts                 # hanzo kms zk invite
│       ├── rotate.ts                 # hanzo kms zk rotate
│       ├── recover.ts                # hanzo kms zk recover
│       └── status.ts                 # hanzo kms zk status

mpc-node/                             # MPC node binary (Go, distributed)
├── go.mod                            # github.com/hanzoai/kms/mpc-node
├── main.go                           # Node entry point (gRPC + gossip)
├── node.go                           # Node lifecycle, peer discovery
├── evaluator.go                      # TFHE policy evaluation
├── store.go                          # ZapDB storage layer
├── crdt.go                           # FHE-encrypted CRDT sync
├── ceremony.go                       # MPC key ceremonies (luxfi/mpc)
├── threshold.go                      # Shamir shard management (luxfi/threshold)
├── types.go                          # Protobuf-generated types
└── proto/
    ├── mpc_node.proto                # Node-to-node gossip protocol
    └── fhe_eval.proto                # FHE evaluation service definition
```

## ZapDB Storage Schema

Each MPC node stores data in its local ZapDB instance (`luxfi/zapdb`).
ZapDB is a BadgerDB fork -- embedded, pure Go, SSI transactions, encrypted at rest.
No external database process. No network-accessible DB.

```go
// Key prefixes for ZapDB (byte-oriented KV store)
const (
    // Encrypted secret blobs (replicated via CRDT)
    PrefixBlob      = "blob:"       // blob:{org_id}:{secret_id}:{cek_version} → encrypted payload

    // FHE metadata (replicated via CRDT)
    PrefixFHE       = "fhe:"        // fhe:{org_id}:{secret_id} → TFHE ciphertexts

    // Wrapped CEKs for org members (replicated via CRDT)
    PrefixMemberKey = "mkey:"       // mkey:{org_id}:{member_id}:{cek_version} → HPKE-wrapped CEK

    // Org config (replicated via CRDT)
    PrefixOrgConfig = "orgcfg:"     // orgcfg:{org_id} → threshold config, wrapping pubkey, etc.

    // This node's Shamir shard (local only, NOT replicated)
    PrefixShard     = "shard:"      // shard:{org_id} → encrypted Shamir share

    // CRDT vector clock (local only)
    PrefixClock     = "clock:"      // clock:{org_id} → vector clock state
)

// All values are encrypted at rest by ZapDB's built-in encryption.
// Shard values are additionally encrypted with the node's identity key.
// Blob/FHE/MemberKey values are client-encrypted -- ZapDB encryption is defense-in-depth.
```

## API Surface

### Server Endpoints (Fastify)

```
POST   /v1/orgs/:org/zk/init                    # Bootstrap ZK mode for org
GET    /v1/orgs/:org/zk/status                   # Check ZK mode status + threshold config
POST   /v1/orgs/:org/zk/members                  # Add member (wrapped CEK)
GET    /v1/orgs/:org/zk/members/me/wrapped-cek   # Get my wrapped CEK
DELETE /v1/orgs/:org/zk/members/:id               # Revoke member access
PUT    /v1/orgs/:org/zk/rotate                    # CEK rotation (MPC ceremony + bulk blob replace)
POST   /v1/orgs/:org/zk/recover                   # Recovery ceremony (verify hash)

POST   /v1/orgs/:org/zk/secrets                  # Store encrypted blob + FHE metadata
GET    /v1/orgs/:org/zk/secrets                   # List encrypted blobs (still opaque)
GET    /v1/orgs/:org/zk/secrets/:id               # Get single encrypted blob
PUT    /v1/orgs/:org/zk/secrets/:id               # Update encrypted blob
DELETE /v1/orgs/:org/zk/secrets/:id               # Delete encrypted blob

GET    /v1/orgs/:org/zk/policies/evaluate         # Trigger distributed FHE policy evaluation
GET    /v1/orgs/:org/zk/policies/results          # Get encrypted policy results

GET    /v1/orgs/:org/zk/nodes/status              # MPC node cluster health
```

All endpoints require IAM OIDC JWT. Org scoping from `owner` claim.

### Client SDK Methods

```typescript
// @hanzo/kms-zk-sdk

class HanzoKmsZkClient {
  // Initialization
  static async bootstrap(
    orgSlug: string,
    passphrase: string,
    opts?: { threshold?: number; nodes?: number }  // default 2-of-3
  ): Promise<HanzoKmsZkClient>
  static async unlock(orgSlug: string, wrappedCek: Buffer, privateKey: Buffer): Promise<HanzoKmsZkClient>

  // Secret operations (all client-side encrypt/decrypt)
  async createSecret(key: string, value: string, opts?: SecretOpts): Promise<SecretRef>
  async getSecret(id: string): Promise<{key: string, value: string}>
  async updateSecret(id: string, value: string): Promise<void>
  async deleteSecret(id: string): Promise<void>
  async listSecrets(): Promise<SecretRef[]>

  // Member management
  async inviteMember(memberId: string, memberPubkey: Buffer): Promise<void>
  async revokeMember(memberId: string): Promise<void>

  // Key rotation (triggers MPC ceremony)
  async rotateCek(): Promise<void>

  // Recovery
  async generateRecoveryShares(n: number, t: number): Promise<Buffer[]>
  static async recover(orgSlug: string, shares: Buffer[]): Promise<HanzoKmsZkClient>

  // Policy (encrypted results, decrypted client-side)
  async evaluatePolicies(): Promise<PolicyResult[]>

  // Cluster info
  async getNodeStatus(): Promise<NodeStatus[]>
}
```

### MPC Node gRPC Services

```protobuf
syntax = "proto3";
package hanzo.kms.mpc;

// Service exposed to KMS API server
service MpcNode {
  // Distribute a Shamir shard to this node during org bootstrap
  rpc StoreShard(StoreShardRequest) returns (StoreShardResponse);

  // Store/retrieve encrypted blobs (CRDT-replicated across nodes)
  rpc PutBlob(PutBlobRequest) returns (PutBlobResponse);
  rpc GetBlob(GetBlobRequest) returns (GetBlobResponse);
  rpc ListBlobs(ListBlobsRequest) returns (ListBlobsResponse);

  // FHE policy evaluation
  rpc EvaluatePolicies(EvaluatePoliciesRequest) returns (EvaluatePoliciesResponse);

  // Key ceremony participation
  rpc InitiateCeremony(CeremonyRequest) returns (CeremonyResponse);

  // Health
  rpc Health(HealthRequest) returns (HealthResponse);
}

// Node-to-node gossip (internal, not exposed to KMS API)
service NodeGossip {
  rpc SyncCRDT(CRDTSyncRequest) returns (CRDTSyncResponse);
  rpc PropagateBlob(PropagateBlobRequest) returns (PropagateBlobResponse);
}

message StoreShardRequest {
  string org_id = 1;
  bytes encrypted_shard = 2;     // HPKE-encrypted Shamir share
  uint32 threshold = 3;          // t value
  uint32 total_nodes = 4;        // n value
}

message EvaluatePoliciesRequest {
  string org_id = 1;
  repeated PolicyCheck checks = 2;
}

message PolicyCheck {
  string secret_id = 1;
  PolicyType type = 2;
  bytes encrypted_lhs = 3;
  bytes encrypted_rhs = 4;
}

enum PolicyType {
  EXPIRY_CHECK = 0;
  ROTATION_DUE = 1;
  ACCESS_LIMIT = 2;
}

message EvaluatePoliciesResponse {
  repeated PolicyResult results = 1;
}

message PolicyResult {
  string secret_id = 1;
  PolicyType type = 2;
  bytes encrypted_result = 3;    // TFHE encrypted boolean
}

message CeremonyRequest {
  string org_id = 1;
  CeremonyType type = 2;
  bytes payload = 3;             // ceremony-specific data
}

enum CeremonyType {
  KEY_ROTATION = 0;
  RECOVERY = 1;
  THRESHOLD_CHANGE = 2;
}
```

## luxfi Package Usage

| Package | Version | Usage |
|---------|---------|-------|
| `luxfi/zapdb` | v4.x | Embedded encrypted KV store, one instance per MPC node. BadgerDB fork with SSI transactions. |
| `luxfi/fhe` | v1.7.x | TFHE encrypt/decrypt/evaluate in MPC nodes; FHE CRDT implementation; `@luxfhe/wasm` in browser SDK |
| `luxfi/lattice` | v7.x | Indirect dependency via `luxfi/fhe` (ring arithmetic, NTT). Not used directly. |
| `luxfi/crypto/encryption` | v1.x | HPKE key wrapping (ML-KEM-768+X25519 hybrid). Used in MPC nodes and client SDK. |
| `luxfi/crypto/secret` | v1.x | `secret.Do()` for runtime key material protection in MPC nodes |
| `luxfi/crypto` | v1.x | Shamir split/combine, HKDF, AEAD primitives |
| `luxfi/threshold` | v1.x | Threshold signature operations for MPC ceremonies |
| `luxfi/mpc` | v1.x | Multi-party computation protocol for key ceremonies (generation, rotation, recovery) |
| `luxfi/fhe-coprocessor` | v1.x | Reference for FHE evaluation patterns. We embed the evaluator in each MPC node, not as a sidecar. |
| `luxfi/crypto/mlkem` | v1.x | ML-KEM-768 for post-quantum CEK wrapping (used via HPKE hybrid from day one) |

### What We Do NOT Use

- `luxfi/lattice` directly -- too low-level; `luxfi/fhe` wraps it
- `luxfi/crypto/bls` -- not relevant; BLS is for consensus signatures, not encryption
- `luxfi/crypto/secp256k1` -- not relevant; Ethereum signing, not KMS encryption
- Any external FHE library (SEAL, OpenFHE, HElib) -- `luxfi/fhe` is our stack
- PostgreSQL, SQLite, or any external database -- ZapDB embedded per node
- Sidecar pattern for FHE -- TFHE is distributed by nature

## Migration Plan

### Phase 1: MPC Node Infrastructure (Week 1-2)

1. **MPC node binary**: Build `mpc-node/` Go binary with ZapDB, gRPC, gossip protocol
2. **ZapDB integration**: Per-node encrypted storage, key prefix schema, SSI transactions
3. **Node discovery**: Gossip-based peer discovery for MPC node cluster
4. **SDK skeleton**: Create `@hanzo/kms-zk-sdk` package with key derivation and AES-256-GCM
5. **CLI skeleton**: Add `hanzo kms zk` subcommand group with `--threshold` and `--nodes` flags

### Phase 2: Core ZK Flow (Week 3-4)

1. **Org bootstrap**: `zk init` command + `/v1/orgs/:org/zk/init` endpoint + Shamir shard distribution
2. **Secret CRUD**: Client-side encrypt/decrypt with CEK, MPC nodes store blobs via CRDT
3. **Member invitation**: HPKE wrapping flow (ML-KEM-768+X25519 hybrid from day one)
4. **Recovery shares**: Shamir split/combine integrated with MPC ceremony protocol

### Phase 3: FHE Policy Evaluation (Week 5-6)

1. **FHE metadata**: Client generates TFHE-encrypted metadata on secret create/update
2. **Distributed evaluation**: Each MPC node evaluates TFHE gates independently
3. **CRDT sync**: FHE-encrypted CRDT merge of evaluation results across nodes
4. **Result delivery**: Client fetches and decrypts policy results

### Phase 4: Migration Tooling (Week 7-8)

1. **Legacy migration command**: `hanzo kms zk migrate`
   - Reads existing secrets (server decrypts with legacy root key)
   - Client re-encrypts with new CEK
   - Distributes encrypted blobs to MPC nodes
   - Marks org as `zk_enabled`
2. **Dual-mode operation**: Server serves both legacy and ZK endpoints during migration
3. **Legacy deprecation**: After all orgs migrated, legacy decrypt paths become no-ops

### Phase 5: Hardening (Week 9-10)

1. **Threshold tuning**: Per-org threshold configuration UI in platform.hanzo.ai
2. **Key ceremony automation**: Automated rotation ceremonies via `luxfi/mpc`
3. **Formal audit**: External review of Shamir implementation, FHE evaluation, CRDT convergence
4. **Chaos testing**: Kill MPC nodes, verify t-of-n reconstruction and CRDT re-sync

## Security Properties

### What the Server Cannot Do

1. **Read secret values** -- encrypted with client-held CEK, AES-256-GCM
2. **Derive the CEK** -- requires admin passphrase + Argon2id (256MiB memory-hard)
3. **Read FHE metadata values** -- TFHE ciphertexts, eval keys can compute but not decrypt
4. **Forge policy results** -- results are TFHE-encrypted booleans, client verifies by decrypting
5. **Impersonate members** -- HPKE wrapping requires member's private key (from IAM)
6. **Reconstruct master key** -- Shamir shards distributed to MPC nodes, server has none

### What an Individual MPC Node Cannot Do

1. **Reconstruct the master key** -- holds only 1 shard, needs t shards (information-theoretic security)
2. **Decrypt secret payloads** -- encrypted with CEK, which is derived from master key
3. **See other nodes' shards** -- each shard is encrypted with the receiving node's key
4. **Forge CRDT state** -- LWW-Register with FHE-encrypted timestamps, deterministic merge

### What the Server CAN Do

1. **Delete encrypted blobs** -- availability attack, not confidentiality. Mitigated by CRDT replication across MPC nodes.
2. **Replay old blobs** -- mitigated by cek_version + monotonic version counter in CRDT
3. **Deny service** -- standard DoS. Mitigated by standard infra (rate limiting, replicas)
4. **See access patterns** -- who accessed which secret_id, when. This is the audit log. Metadata is visible by design.
5. **Route to wrong MPC nodes** -- mitigated by client-side node verification (node identity keys in IAM)

### Threat Model Boundaries

- **Compromised server**: Cannot read secrets. Cannot reconstruct master key. Can disrupt availability. Cannot forge policies (client verifies).
- **Compromised t-1 MPC nodes**: Information-theoretically secure. t-1 nodes learn nothing about master key. FHE eval keys are per-node -- no cross-node leakage.
- **Compromised t MPC nodes**: Master key can be reconstructed. Mitigate: deploy nodes across failure domains (different clusters, different providers). Monitor node health.
- **Compromised admin passphrase**: Attacker derives CEK, reads all org secrets. Mitigate: strong passphrase policy, HSM-backed credentials in enterprise.
- **Compromised member device**: Attacker gets that member's CEK copy. Mitigate: member revocation re-wraps CEK, old wrapped blob is useless.
- **Quantum adversary**: ML-KEM-768+X25519 hybrid HPKE is post-quantum secure. TFHE (lattice-based) is post-quantum secure. Argon2id retains 128-bit security under Grover.

## Trade-offs

| Trade-off | What we gave up | Why it is acceptable |
|-----------|----------------|---------------------|
| No centralized DB | SQL queries, joins, ad-hoc analytics on secret metadata | KMS is not a database. Key-value access patterns only. ZapDB handles this. Analytics on audit log (append-only, separate concern). |
| Client-side compute for rotation | CEK rotation requires client to re-encrypt all secrets | Rotation is rare (monthly/quarterly). Client can batch. Server cannot do it because server has no CEK. |
| FHE metadata overhead | Each secret has ~1KB of TFHE ciphertexts alongside the AES blob | Small relative to secret payloads. Enables policy evaluation without plaintext. |
| No server-side search | Server cannot search secret names/values | Client downloads encrypted list, decrypts, searches locally. Acceptable for KMS (not a database). |
| Argon2id latency | First unlock takes ~1 second (256MiB memory-hard) | Happens once per session. CEK is cached in memory afterward. Security requires it. |
| Distributed node complexity | More moving parts than a monolith | TFHE is inherently distributed. Fighting this creates worse architecture (centralized DB + sidecar). Embrace the natural model. |
| MPC ceremony latency | Key rotation/recovery requires t nodes to participate | Ceremonies are rare. Latency is seconds, not minutes. Automated via luxfi/mpc. |

## Deployment

```yaml
# MPC nodes deployed as independent StatefulSets in hanzo-k8s (Kustomize overlay)
# Each node gets its own PVC for ZapDB data.
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: kms-mpc
  namespace: hanzo
spec:
  replicas: 3  # default: 3 nodes for 2-of-3 threshold
  serviceName: kms-mpc
  template:
    spec:
      containers:
        - name: mpc-node
          image: ghcr.io/hanzoai/kms-mpc-node:latest
          ports:
            - containerPort: 9090   # gRPC (API server → node)
              name: grpc
            - containerPort: 9091   # Prometheus metrics
              name: metrics
            - containerPort: 9092   # Gossip (node-to-node CRDT sync)
              name: gossip
          env:
            - name: NODE_ID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: ZAPDB_ENCRYPTION_KEY
              valueFrom:
                secretKeyRef:
                  name: kms-mpc-node-keys
                  key: zapdb-key  # From KMS, unique per node
            - name: GOSSIP_PEERS
              value: "kms-mpc-0.kms-mpc:9092,kms-mpc-1.kms-mpc:9092,kms-mpc-2.kms-mpc:9092"
          resources:
            requests:
              memory: "512Mi"
              cpu: "500m"
            limits:
              memory: "2Gi"
              cpu: "2"
          volumeMounts:
            - name: zapdb-data
              mountPath: /data/zapdb
          livenessProbe:
            grpc:
              port: 9090
            initialDelaySeconds: 10
          readinessProbe:
            grpc:
              port: 9090
            initialDelaySeconds: 5
  volumeClaimTemplates:
    - metadata:
        name: zapdb-data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 10Gi
---
# KMS API server (stateless, Fastify)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kms
  namespace: hanzo
spec:
  template:
    spec:
      containers:
        - name: kms
          image: ghcr.io/hanzoai/kms:latest
          ports:
            - containerPort: 8080
          env:
            - name: MPC_NODE_ADDRS
              value: "kms-mpc-0.kms-mpc:9090,kms-mpc-1.kms-mpc:9090,kms-mpc-2.kms-mpc:9090"
            # No ROOT_ENCRYPTION_KEY for ZK-enabled orgs
            # Legacy orgs still use it during migration
```

MPC nodes run as a StatefulSet with persistent ZapDB storage. Each node is
independently addressable via the headless service. Gossip protocol handles
CRDT sync. The KMS API server is a stateless Deployment that routes to the
MPC node cluster via gRPC.

## Monitoring

- **MPC node metrics**: TFHE gate evaluation latency, eval count, error rate, ZapDB compaction stats, CRDT sync lag, shard health (Prometheus at `:9091/metrics`)
- **KMS API metrics**: ZK endpoint latency, blob size distribution, member count per org, MPC node connectivity
- **CRDT metrics**: Sync frequency, merge conflicts (should be zero for LWW), convergence time
- **Alerts**:
  - FHE evaluation failures on any node
  - MPC node down (if remaining nodes < t for any org, critical alert)
  - CEK rotation overdue (based on encrypted policy results from client reports)
  - ZapDB disk usage > 80%
  - CRDT sync lag > 30 seconds

## What This Document Is Not

This is not a standalone cryptographic proof publication. It is an engineering
architecture with formal proof sketches that establish the security reduction
chain. The cryptographic primitives (AES-256-GCM, Argon2id, HKDF-SHA256,
HPKE RFC 9180, TFHE, Shamir SSS, ML-KEM-768) are established and well-analyzed.
The security of this system reduces to the security of those primitives plus
correct implementation. The latter requires code review, testing, and audit --
not more documentation.
