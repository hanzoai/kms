# Sovereign KMS Architecture (Session-KMS Tier)

**Status**: Architecture Decision Record
**Date**: 2026-03-25
**Author**: CTO
**Depends On**: TFHE-KMS-ARCHITECTURE.md (base tier)

## Problem Statement

The TFHE-KMS tier (base KMS) eliminates plaintext secret exposure at the server,
but still requires IP-visible gRPC between clients, the KMS API server, and MPC
nodes. A state-level adversary with network-level surveillance can:

1. Correlate client IPs to secret access patterns (traffic analysis).
2. Selectively block or delay MPC node communication (censorship).
3. Compromise individual MPC nodes via targeted physical/network attacks.

**Goal**: Build a Sovereign tier on top of TFHE-KMS that provides:

- **Network-level anonymity**: No participant's IP is visible to any other.
- **Censorship resistance**: Key ceremonies complete even under active blocking.
- **Post-quantum on-chain anchoring**: All key lifecycle events are verifiable on
  Pars L1 using ML-DSA/SLH-DSA precompiles.
- **FHE-encrypted state sync**: MPC node state replication without plaintext exposure.

**Constraints**:

- SessionVM swarm provides the onion-routing substrate (luxfi/session, luxtel fork).
- Pars L1 provides post-quantum signature verification via native precompiles.
- MPC nodes use luxfi/threshold (Shamir) + luxfi/fhe (TFHE) + luxfi/frost (threshold sigs).
- luxfi packages only. No external crypto libraries.
- Go packages at v1.x.x.
- Secrets in KMS, never in env files, never in git.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│ Client (SDK / CLI / Browser WASM)                                   │
│                                                                     │
│  CEK derived locally (Argon2id). Never leaves client.               │
│  All payloads AES-256-GCM encrypted before transmission.            │
│  Post-quantum key agreement via ML-KEM-768.                         │
│                                                                     │
│  Client connects to SessionVM swarm via onion circuit.              │
│  No IP exposed to KMS API or MPC nodes.                             │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ Onion-routed (3+ hops via SessionVM)
                            │ ML-KEM-768 encrypted per-hop
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│ SessionVM Swarm (Lux Network)                                       │
│                                                                     │
│  Onion routing layer. Each hop is a SessionVM storage node.         │
│  Post-quantum transport: ML-KEM-768 key agreement per hop.          │
│  Session IDs: "07" prefix + ML-DSA-65 pubkey hash.                  │
│                                                                     │
│  Properties:                                                        │
│  - No single node sees both source and destination.                 │
│  - Path selection is client-side (no central directory).             │
│  - Nodes identified by PQ session IDs, not IPs.                     │
│  - Minimum 3-hop circuits for sender anonymity.                     │
│  - Guard nodes rotated on configurable intervals.                   │
│                                                                     │
│  SessionVM nodes run as validators on Lux Network.                  │
│  Sybil resistance via staking (economic, not computational).        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ Encrypted payloads (onion-unwrapped)
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│ KMS API Server (Sovereign Mode)                                     │
│                                                                     │
│  Identical to base TFHE-KMS API, with two additions:                │
│  1. Accepts connections only via SessionVM (no direct IP).           │
│  2. Emits PQ-signed audit anchors to Pars L1.                       │
│                                                                     │
│  The API server itself runs as a SessionVM hidden service.           │
│  Its session ID is published in the org's Pars L1 registry.         │
│                                                                     │
│  Still zero-knowledge: no CEK, no master key, no plaintext.         │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ gRPC over SessionVM inter-node channels
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│ MPC Node Cluster (Sovereign Configuration)                          │
│                                                                     │
│  Each MPC node runs on a DIFFERENT SessionVM swarm node.            │
│  Nodes communicate via onion-routed inter-service channels.         │
│  No MPC node knows any other MPC node's IP.                         │
│                                                                     │
│  ┌─────────────────────┐      ┌─────────────────────┐              │
│  │ MPC Node A          │      │ MPC Node B          │              │
│  │ (SessionVM node X)  │◄────►│ (SessionVM node Y)  │              │
│  │                     │      │                     │              │
│  │ ┌─────────────────┐ │      │ ┌─────────────────┐ │              │
│  │ │ ZapDB (local)   │ │      │ │ ZapDB (local)   │ │              │
│  │ │ AES-256-GCM     │ │      │ │ AES-256-GCM     │ │              │
│  │ └─────────────────┘ │      │ └─────────────────┘ │              │
│  │ ┌─────────────────┐ │      │ ┌─────────────────┐ │              │
│  │ │ Shamir Shard    │ │      │ │ Shamir Shard    │ │              │
│  │ │ (t-of-n)        │ │      │ │ (t-of-n)        │ │              │
│  │ └─────────────────┘ │      │ └─────────────────┘ │              │
│  │ ┌─────────────────┐ │      │ ┌─────────────────┐ │              │
│  │ │ FHE Evaluator   │ │      │ │ FHE Evaluator   │ │              │
│  │ │ (TFHE gates)    │ │      │ │ (TFHE gates)    │ │              │
│  │ └─────────────────┘ │      │ └─────────────────┘ │              │
│  │ ┌─────────────────┐ │      │ ┌─────────────────┐ │              │
│  │ │ FROST Signer    │ │      │ │ FROST Signer    │ │              │
│  │ │ (threshold sig) │ │      │ │ (threshold sig) │ │              │
│  │ └─────────────────┘ │      │ └─────────────────┘ │              │
│  └─────────────────────┘      └─────────────────────┘              │
│           ▲                            ▲                            │
│           │  FHE CRDT Sync             │                            │
│           │  (encrypted, via SessionVM)│                            │
│           └────────────────────────────┘                            │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ FROST threshold signature
                            │ (t-of-n MPC nodes co-sign)
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Pars L1 (Post-Quantum Signature Anchoring)                          │
│                                                                     │
│  On-chain contracts verify:                                         │
│  - Key ceremony completion (ML-DSA-65 signatures)                   │
│  - Audit log anchors (SLH-DSA-SHA2-128s signatures)                 │
│  - MPC quorum attestations (FROST threshold signatures)             │
│  - Org registry updates (ML-DSA-65 org admin signatures)            │
│                                                                     │
│  Precompiles used:                                                  │
│  - 0x0200..0006: ML-DSA verify (key ceremony, identity)             │
│  - 0x0600..0001: SLH-DSA verify (audit anchors, long-term)          │
│  - 0x0200..000C: FROST verify (MPC quorum attestations)             │
│  - 0x0200..0008: PQCrypto unified (ML-KEM for on-chain escrow)      │
│  - 0x0200..0080: FHE (encrypted policy evaluation on-chain)         │
│                                                                     │
│  All signatures are post-quantum. No ECDSA in the critical path.    │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Ceremonies

### 1. Org Onboarding (Master Key Generation)

```
1. Client generates ML-DSA-65 identity keypair locally.
2. Client opens 3-hop SessionVM circuit to KMS API hidden service.
3. Client requests new org provisioning.
4. KMS API broadcasts to MPC node cluster (via SessionVM inter-node):
   a. Each MPC node generates a random contribution.
   b. Contributions are combined via distributed key generation (DKG).
   c. Result: Shamir shares of org master key, threshold t-of-n.
   d. Each node stores its share in local ZapDB (encrypted at rest).
5. MPC nodes co-sign a FROST attestation of ceremony completion.
6. FROST signature + org ML-DSA-65 public key submitted to Pars L1.
7. Pars L1 KeyCeremony contract verifies:
   a. FROST signature (0x0200..000C precompile).
   b. ML-DSA-65 org identity (0x0200..0006 precompile).
   c. Emits OrgRegistered event with on-chain timestamp.
```

### 2. Secret Storage

```
1. Client derives CEK from admin credentials (Argon2id, locally).
2. Client encrypts secret payload with AES-256-GCM using CEK.
3. Client generates FHE-encrypted metadata (access policy, TTL, tags).
4. Client sends encrypted blob + FHE metadata via SessionVM circuit.
5. KMS API routes to MPC cluster.
6. Each MPC node:
   a. Stores encrypted blob shard (Shamir-split the ciphertext).
   b. Evaluates FHE-encrypted policy gates (without seeing policy).
   c. Syncs state via FHE CRDT over SessionVM inter-node channels.
7. MPC nodes co-sign storage attestation (FROST).
8. FROST attestation anchored to Pars L1 (SLH-DSA-SHA2-128s for longevity).
```

### 3. Secret Retrieval

```
1. Client opens SessionVM circuit to KMS API.
2. Client presents ML-DSA-65 signed retrieval request.
3. KMS API forwards to MPC cluster via SessionVM.
4. Each MPC node:
   a. Evaluates FHE-encrypted access policy (is requester authorized?).
   b. If authorized: contributes its Shamir share of the encrypted blob.
   c. Shares transmitted via SessionVM (onion-routed between nodes).
5. Client receives t shares, reconstructs encrypted blob.
6. Client decrypts with local CEK.
7. At no point does any single MPC node, the KMS API, or any
   SessionVM relay node see the plaintext secret.
```

### 4. Key Rotation

```
1. Org admin initiates rotation via ML-DSA-65 signed request.
2. MPC cluster performs proactive secret sharing:
   a. New Shamir shares generated without reconstructing master key.
   b. Old shares invalidated.
   c. Re-encryption of stored blobs under new shares.
3. Rotation attestation co-signed (FROST) and anchored to Pars L1.
4. On-chain KeyRotated event with new epoch number.
```

## FHE CRDT Sync Protocol

MPC nodes must maintain consistent state without a central database.

```
State Model: G-Counter CRDT (grow-only counter set)
Encoding:    All CRDT values are FHE-encrypted (CKKS via luxfi/lattice)
Transport:   SessionVM inter-node channels (onion-routed)
Conflict:    Merge function operates on encrypted values (FHE.add)
Consistency: Eventual consistency with causal ordering (vector clocks)

Each node maintains:
- Encrypted secret registry (FHE ciphertext handles)
- Encrypted access counters (rate limiting via FHE comparison)
- Encrypted policy state (authorization decisions via FHE gates)

Merge protocol:
1. Node A sends FHE-encrypted delta to Node B via SessionVM.
2. Node B applies FHE.add/FHE.max on encrypted deltas.
3. No node sees any other node's plaintext state.
4. Consistency verified by periodic FROST-signed state hashes
   anchored to Pars L1.
```

## Security Properties

### Network Anonymity

| Property | Mechanism |
|----------|-----------|
| Client IP hidden from KMS API | 3-hop SessionVM onion circuit |
| Client IP hidden from MPC nodes | KMS API is intermediary + SessionVM |
| MPC node IPs hidden from each other | Each on different SessionVM node |
| KMS API IP hidden from clients | Hidden service (session ID only) |
| Traffic analysis resistance | Constant-rate padding on SessionVM channels |

### Post-Quantum Resistance

| Threat | Protection |
|--------|------------|
| Quantum key recovery | ML-KEM-768 key agreement (NIST Level 3) |
| Quantum signature forgery | ML-DSA-65 (identity), SLH-DSA (audit anchors) |
| Harvest-now-decrypt-later | All transport is PQ-encrypted end-to-end |
| On-chain signature forgery | Pars precompiles verify PQ signatures natively |

### Censorship Resistance

| Threat | Protection |
|--------|------------|
| Network-level blocking of MPC nodes | Nodes on different SessionVM swarm nodes, no static IPs |
| Selective ceremony disruption | DKG requires only t-of-n, tolerates n-t failures |
| DNS poisoning | No DNS; session IDs published on Pars L1 (immutable) |
| BGP hijacking | SessionVM routing is overlay, not dependent on IP routing |

### Separation of Concerns

```
Client:     Holds CEK. Can encrypt/decrypt. Cannot access without MPC quorum.
KMS API:    Routes requests. Cannot decrypt. Cannot reconstruct master key.
MPC Node:   Holds one Shamir share. Cannot decrypt alone. Cannot see other nodes' shares.
SessionVM:  Routes packets. Cannot read payloads (onion-encrypted). Cannot correlate endpoints.
Pars L1:    Verifies signatures. Cannot decrypt anything. Provides immutable audit trail.
```

## Deployment Topology

```
Minimum viable deployment: 5 MPC nodes, threshold 3-of-5.

MPC Node 1  →  SessionVM swarm node (region A)
MPC Node 2  →  SessionVM swarm node (region B)
MPC Node 3  →  SessionVM swarm node (region C)
MPC Node 4  →  SessionVM swarm node (region D)
MPC Node 5  →  SessionVM swarm node (region E)

KMS API     →  SessionVM hidden service (any region, no IP exposed)

Each MPC node is a standalone Go binary:
- Embedded ZapDB for local state
- luxfi/session SDK for SessionVM transport
- luxfi/threshold for Shamir operations
- luxfi/fhe for TFHE evaluation
- luxfi/frost for threshold signatures
- luxfi/crypto/mldsa + luxfi/crypto/slhdsa for PQ identity

No shared database. No shared filesystem. No coordinator process.
```

## Component Dependencies

| Component | Package | Purpose |
|-----------|---------|---------|
| Onion routing | luxfi/session | SessionVM swarm transport |
| PQ key agreement | luxfi/crypto/mlkem | ML-KEM-768 per-hop encryption |
| PQ identity | luxfi/crypto/mldsa | ML-DSA-65 node/org identity |
| PQ audit sigs | luxfi/crypto/slhdsa | SLH-DSA long-term audit anchors |
| Secret splitting | luxfi/threshold | Shamir t-of-n sharing |
| Threshold sigs | luxfi/frost | FROST co-signing for attestations |
| FHE evaluation | luxfi/fhe (luxfi/lattice) | TFHE gates for encrypted policy |
| CRDT sync | luxfi/fhe | FHE-encrypted merge operations |
| On-chain verify | Pars precompiles | ML-DSA, SLH-DSA, FROST, FHE |
| Local storage | ZapDB | Embedded, encrypted at rest |
| Key derivation | golang.org/x/crypto | Argon2id (client-side CEK) |

## Migration Path (Base TFHE-KMS to Sovereign)

```
Phase 1: Deploy SessionVM transport alongside existing gRPC.
         MPC nodes accept both direct gRPC and SessionVM channels.
         Clients can opt-in to SessionVM circuits.
         No on-chain anchoring yet.

Phase 2: Deploy Pars L1 anchoring.
         Key ceremonies emit FROST attestations to chain.
         Audit logs anchored via SLH-DSA signatures.
         Direct gRPC still available as fallback.

Phase 3: Deprecate direct gRPC.
         All communication via SessionVM only.
         KMS API becomes hidden service.
         MPC nodes reachable only via session IDs.

Phase 4: Full sovereign mode.
         Org registry on Pars L1 (session IDs, PQ public keys).
         No IP addresses in any configuration.
         All state sync via FHE CRDTs over SessionVM.
```

## Threat Model

### In Scope

- State-level network surveillance (passive traffic analysis).
- Active network adversary (selective blocking, injection).
- Compromised KMS API server (full server compromise).
- Compromised minority of MPC nodes (up to t-1 of n).
- Quantum adversary (Shor's algorithm for key recovery).
- Harvest-now-decrypt-later (recording encrypted traffic for future quantum attack).

### Out of Scope

- Client device compromise (CEK stored on client; if device is owned, game over).
- Compromised majority of MPC nodes (t or more of n colluding).
- Side-channel attacks on individual MPC node hardware.
- Bugs in luxfi/lattice or luxfi/crypto implementations (assumed correct).

### Residual Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| SessionVM swarm eclipse attack | Medium | Economic: staking cost for Sybil; guard node rotation |
| FHE evaluation performance | Low | CKKS parameters tuned for policy gates, not general compute |
| FROST liveness (< t nodes online) | Medium | Over-provision n; monitor via on-chain heartbeats |
| Pars L1 chain halt | Low | Ceremonies complete without anchoring; anchor when chain resumes |
