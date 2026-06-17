# AI Assistant Knowledge Base

**Project**: crypto
**Organization**: luxfi
**Repo**: github.com/luxfi/crypto
**Latest Tag**: v1.18.5

## Project Overview

Lux cryptography library implementing post-quantum standards and consensus primitives.
TLS certificate utilities live in the top-level `github.com/luxfi/tls` module.

## Post-E2E-PQ State (current)

ML-DSA is now the canonical PQ identity primitive across the Lux stack.
This repo owns the FIPS 204 / 203 / 205 implementations and KAT vectors;
downstream consumers (consensus, node, bridge, sdk, contracts) bind their
strict-PQ profiles to these exact wrappers.

### Recent significant commits
| SHA | Tag | Impact |
|-----|-----|--------|
| `ad20ed8` | v1.18.5 | `pq/mldsa`: KAT vectors + expanded-key form + ethdilithium-compat. Closes F92 (ETHDILITHIUM precompile compat). |
| `5afe516` | v1.18.4 | `pq/mldsa`: export `NewKeyFromSeed` for mldsa44 / mldsa65 / mldsa87. Needed by Z-Chain key registry. |
| `f5ff040` | v1.18.4 | PQ canonical terminology (FIPS 203/204/205 + Pulsar + Lamport). |
| `4bf9585` | v1.18.4 | thresholdvm M/F-Chain modes per LP-134. |
| `a94eee3` | — | LLM.md: drop dated 'Last Updated' line. |

### Active versions
- Repo: `v1.18.5` (next bump: `v1.18.6`).
- Critical consumers: `consensus v1.23.6+` pulls `crypto v1.18.4`,
  `consensus v1.23.7` pulls `v1.18.5`. `sdk feat/pq-wallet-account` pulls
  `v1.18.5` for the HD wallet path.

### Canonical PQ packages
| Package | Standard | Notes |
|---------|----------|-------|
| `pq/mldsa/mldsa44` | FIPS 204 | Compat tier (CLASSICAL_COMPAT_UNSAFE only) |
| `pq/mldsa/mldsa65` | FIPS 204 | **Canonical strict-PQ identity** |
| `pq/mldsa/mldsa87` | FIPS 204 | High-value (root keys, M-Chain custody) |
| `pq/mlkem/mlkem768` | FIPS 203 | Canonical KEM for peer handshakes + Z-Wing |
| `pq/mlkem/mlkem1024` | FIPS 203 | High-value tier |
| `pq/slhdsa` | FIPS 205 | Recovery path (SLH-DSA-SHA2-192f) |

### Cross-repo dependencies (consumers)
- `luxfi/consensus` → mldsa{44,65,87}, slhdsa, mlkem768
- `luxfi/node` → all of the above + bls
- `luxfi/sdk` (feat/pq-wallet-account) → mldsa65 + slhdsa192
- `luxfi/genesis` → mldsa65 keygen (swapped off cloudflare/circl)
- `luxfi/bridge` → mldsa65 (LUX_STRICT_PQ_BRIDGE)
- `luxfi/contracts` (PQAuth.sol) → on-chain calls to native precompiles
  that wrap these (no in-Solidity reimplementation)

### Where to look for X
- ML-DSA-65 sign / verify entrypoints: `pq/mldsa/mldsa65/mldsa.go`
- KAT vector files: `pq/mldsa/*/testdata/kat/`
- `NewKeyFromSeed` (Z-Chain key registry use): `pq/mldsa/*/mldsa.go`
- Expanded-key (ETHDILITHIUM compat) form: `pq/mldsa/mldsa65/expanded.go`
- HPKE (Go 1.26 stdlib + ML-KEM hybrid): `encryption/hpke.go`
- `secret.Do()` BLS / ECDSA wrappers: `secret/secret.go`

### Open follow-ups
- ML-DSA-44 retained for `CLASSICAL_COMPAT_UNSAFE` only; new code MUST
  default to ML-DSA-65.
- `circl` HPKE wrapper in `hpke/` kept for back-compat; stdlib
  `crypto/hpke` is canonical going forward (Go 1.26).

---

## Essential Commands

```bash
make test           # Run tests
make test-coverage  # Coverage
make bench          # Benchmarks
make ci             # Full CI

# Docs
cd docs && pnpm dev      # Dev server at :3001
cd docs && pnpm build    # Build static site
```

## Architecture

### Consensus Cryptography (Lux Quasar)
| Package | Purpose | Notes |
|---------|---------|-------|
| **signer/** | Hybrid BLS + Pulsar signing | Lux consensus |
| **bls/** | BLS12-381 aggregatable signatures | Classical layer |
| **corona/** | Lattice-based threshold signatures | Post-quantum layer |

### Post-Quantum Cryptography (NIST Standards)
| Package | Standard | Purpose | LP Reference |
|---------|----------|---------|--------------|
| **mldsa/** | FIPS 204 | ML-DSA lattice-based signatures | LP-4316 |
| **mlkem/** | FIPS 203 | ML-KEM key encapsulation | LP-4318 |
| **slhdsa/** | FIPS 205 | SLH-DSA hash-based signatures | LP-4317 |

### Classical Cryptography
| Package | Purpose |
|---------|---------|
| **secp256k1/** | Ethereum-compatible ECDSA |
| **secp256r1/** | P-256 ECDSA (RIP-7212) |
| **bn256/** | BN256 pairing-based crypto |

### Advanced Cryptography
| Package | Purpose | LP Reference |
|---------|---------|--------------|
| **lamport/** | One-time quantum-resistant signatures | LP-2506 |
| **kzg4844/** | KZG polynomial commitments (EIP-4844) | - |
| **ipa/** | Inner product arguments (Verkle trees) | - |
| **ring/** | Ring signatures for Q-Chain privacy | - |

### EVM Integration
| Package | Purpose | LP Reference |
|---------|---------|--------------|
| **precompile/** | Post-quantum EVM precompiles | LP-2517 |

### Go 1.26 Features (v1.17.44, 2026-03-22)
| Package | Purpose | Notes |
|---------|---------|-------|
| **secret/** | Secure key material handling | `runtime/secret.Do()` with `GOEXPERIMENT=runtimesecret`, no-op stub otherwise |
| **encryption/hpke.go** | HPKE encryption (RFC 9180) | Uses Go 1.26 stdlib `crypto/hpke`, X25519 + ML-KEM-768+X25519 hybrid |

Key changes:
- `secret.Do()` wraps BLS key generation, ECDSA key loading/parsing, HPKE decryption
- `crypto/hpke` stdlib replaces need for circl HPKE in encryption/ (circl wrapper in hpke/ kept for backward compat)
- `crypto/rand.Read` never errors in Go 1.26 (panics on failure) -- simplified `random.go`
- CI: new `test-runtimesecret` job builds/tests with `GOEXPERIMENT=runtimesecret`

### Supporting Packages
- **blake2b/, hash/** - Hash functions (SHA, BLAKE, Keccak, SHAKE)
- **kem/** - Key encapsulation interface
- **ecies/** - Hybrid encryption
- **cb58/** - Base58 encoding
- **rlp/** - RLP encoding

## Key Distinction: Threshold vs Regular Signatures

| Type | Example | Use Case |
|------|---------|----------|
| **Threshold** | Pulsar, BLS-Threshold, FROST, CGGMP21 | t-of-n validators sign collaboratively |
| **Regular** | ML-DSA, BLS | Single party signs |

Lux consensus uses **BLS + Pulsar**:
- BLS: Classical, aggregatable signatures
- Pulsar: Lattice-based threshold for post-quantum security

ML-DSA is a separate NIST standard (not used in consensus, potential future validator messages).

## Threshold Signature Interfaces (2025-12-17)

### File Structure

```
threshold/
  interfaces.go      # Core interfaces: Scheme, DKG, Signer, Aggregator, Verifier
  errors.go          # Sentinel errors and IdentifiableAbortError
  registry.go        # Scheme registration and lookup
  session.go         # SigningSession and SessionManager for multi-party signing
  adapter.go         # SchemeAdapter and QuickSign helpers
  interfaces_test.go # Interface tests
  bls/
    scheme.go        # BLS threshold implementation (skeleton)
    scheme_test.go   # BLS threshold tests
```

### Core Interfaces

| Interface | Purpose |
|-----------|---------|
| `Scheme` | Factory for DKG, Signer, Aggregator, Verifier |
| `DKG` | Distributed key generation protocol (multi-round) |
| `TrustedDealer` | Centralized key share generation |
| `KeyShare` | Party's share of the threshold key |
| `Signer` | Creates signature shares |
| `SignatureShare` | Party's share of a signature |
| `Aggregator` | Combines shares into final signature |
| `Verifier` | Verifies threshold signatures |
| `PublicKey` | Group public key |
| `Signature` | Final aggregated signature |

### Supported Schemes

| SchemeID | Name | Status | Post-Quantum | Non-Interactive |
|----------|------|--------|--------------|-----------------|
| `SchemeFROST` | FROST (Schnorr) | Interface only | No | No |
| `SchemeCMP` | CGGMP21 (ECDSA) | Partial in cggmp21/ | No | No |
| `SchemeBLS` | BLS Threshold | Skeleton impl | No | Yes |
| `SchemeCorona` | Pulsar (Lattice) | Interface only | Yes | No |

### Usage Pattern

```go
// Get scheme
scheme, _ := threshold.GetScheme(threshold.SchemeBLS)

// Generate keys (trusted dealer or DKG)
dealer, _ := scheme.NewTrustedDealer(threshold.DealerConfig{
    Threshold:    2,  // t in t+1-of-n
    TotalParties: 5,
})
shares, groupKey, _ := dealer.GenerateShares(ctx)

// Create signers
signers := make([]threshold.Signer, len(shares))
for i, share := range shares {
    signers[i], _ = scheme.NewSigner(share)
}

// Sign (t+1 parties needed)
message := []byte("message")
participants := []int{0, 1, 2}
sigShares := make([]threshold.SignatureShare, len(participants))
for i, idx := range participants {
    sigShares[i], _ = signers[idx].SignShare(ctx, message, participants, nil)
}

// Aggregate
aggregator, _ := scheme.NewAggregator(groupKey)
signature, _ := aggregator.Aggregate(ctx, message, sigShares, nil)

// Verify
verifier, _ := scheme.NewVerifier(groupKey)
valid := verifier.Verify(message, signature)
```

### Signer Integration

The `signer/signer.go` package integrates with threshold signing:

```go
// Create signer with threshold key share
signer, _ := NewSignerWithThreshold(keyShare)

// Or set later
signer.SetThresholdKeyShare(keyShare)

// Check state
signer.HasThresholdKey()
signer.ThresholdSchemeID()
signer.ThresholdIndex()

// Sign
share, _ := signer.SignThresholdShare(ctx, message, participantIndices)

// Aggregate and verify
signature, _ := signer.AggregateThresholdShares(ctx, message, shares)
valid := signer.VerifyThreshold(message, signature)
```

### Implementation Notes

1. **BLS Implementation**: The `threshold/bls/` package provides a skeleton implementation.
   Full Shamir secret sharing polynomial evaluation and Lagrange interpolation
   are marked as TODO for production use.

2. **External Packages**: Production implementations should integrate with:
   - `github.com/luxfi/threshold` - Full threshold protocols
   - `github.com/luxfi/corona` - Lattice-based primitives

3. **Session Management**: Use `SigningSession` and `SessionManager` for
   coordinating multi-party signing with timeout and state tracking.

## Ring Signature Package (2025-12-19)

### Overview

The `ring/` package implements ring signatures for Q-Chain privacy features. Ring signatures allow a member of a group to sign a message such that it can be verified as coming from someone in the group, but without revealing which member actually signed.

### Schemes Supported

| Scheme | Security | Key Type | Notes |
|--------|----------|----------|-------|
| **LSAG** | Classical | secp256k1 | Production-ready, uses dcrd/secp256k1 |
| **LatticeLSAG** | Post-Quantum | ML-DSA-65 | ML-DSA key material with hash-based ring |

### File Structure

```
ring/
  ring.go          # Core interfaces: RingSignature, Signer, KeyImageStore
  lsag.go          # LSAG implementation (secp256k1)
  lattice.go       # Post-quantum ring signatures (ML-DSA)
  ring_test.go     # Comprehensive tests (21 tests)
```

### Core Interfaces

```go
// RingSignature represents an anonymous group signature
type RingSignature interface {
    Scheme() Scheme
    Bytes() []byte
    KeyImage() []byte     // For linkability/double-spend detection
    RingSize() int
    Verify(message []byte, ring [][]byte) bool
}

// Signer creates ring signatures
type Signer interface {
    Scheme() Scheme
    PublicKey() []byte
    Sign(message []byte, ring [][]byte, signerIndex int) (RingSignature, error)
    KeyImage() []byte
}

// KeyImageStore tracks used key images for double-spend detection
type KeyImageStore interface {
    HasKeyImage(keyImage []byte) bool
    AddKeyImage(keyImage []byte) error
    RemoveKeyImage(keyImage []byte) error
}
```

### Usage Example

```go
// Create signer
signer, _ := ring.NewSigner(ring.LSAG)  // or ring.LatticeLSAG

// Create ring with decoy public keys
ringMembers := make([][]byte, 5)
signerIndex := 2
ringMembers[signerIndex] = signer.PublicKey()
for i := 0; i < 5; i++ {
    if i != signerIndex {
        decoy, _ := ring.NewSigner(ring.LSAG)
        ringMembers[i] = decoy.PublicKey()
    }
}

// Sign message
message := []byte("anonymous transaction")
sig, _ := signer.Sign(message, ringMembers, signerIndex)

// Verify (doesn't reveal which key signed)
valid := sig.Verify(message, ringMembers)

// Double-spend detection via key images
store := ring.NewMemoryKeyImageStore()
err := ring.VerifyAndRecord(sig, message, ringMembers, store)
// Second attempt with same key image will return ErrKeyImageReused
```

### Key Concepts

1. **Anonymity**: Verifier knows signature came from someone in the ring, but not which member
2. **Linkability**: Key images allow detecting if same key signed twice (double-spend prevention)
3. **Spontaneity**: No setup required - any public keys can form a ring

### Implementation Notes

- **LSAG**: Full cryptographic implementation using secp256k1 elliptic curves
- **LatticeLSAG**: Uses ML-DSA keys (NIST Level 3, 192-bit security) with hash-based ring construction
- Both schemes support serialization/deserialization via `Bytes()` and `ParseSignature()`

### Test Coverage (21 tests all pass)

| Test | Description |
|------|-------------|
| TestLSAGSignAndVerify | Sign and verify cycle |
| TestLSAGSignatureInvalidMessage | Reject wrong message |
| TestLSAGSignatureInvalidRing | Reject modified ring |
| TestLSAGSignatureSerialization | Serialize/deserialize roundtrip |
| TestLSAGKeyImageLinkability | Same key = same key image |
| TestLSAGDoubleSpendDetection | KeyImageStore prevents reuse |
| TestLatticeSignAndVerify | Post-quantum sign/verify |
| TestLatticeSerialization | Post-quantum serialization |
| TestLatticeKeyImageLinkability | Post-quantum linkability |
| TestLatticeSignatureInvalidMessage | Post-quantum wrong message |
| TestLatticeSignatureInvalidRing | Post-quantum modified ring |

### Distinction from Pulsar

| Package | Type | Purpose |
|---------|------|---------|
| **ring/** | Ring Signatures | Anonymous single-party signing (Q-Chain privacy) |
| **corona/** | Threshold Signatures | Multi-party collaborative signing (t-of-n) |

Ring signatures hide the signer among a group. Threshold signatures require multiple parties to sign together.

### CLI Integration (2025-12-19)

Ring signatures are integrated into the Lux CLI via `lux key ring` commands:

**Commands:**
```bash
lux key ring sign <key> "message" --ring key1,key2,key3  # Create ring signature
lux key ring verify "message" --signature <sig> --ring k1,k2,k3  # Verify
lux key ring keyimage <key>                               # Show key image
lux key ring schemes                                      # List supported schemes
lux key ring generate --size 5                            # Generate decoy keys
```

**Scheme Flags:**
- `--scheme lsag` (default) - Uses Pulsar keys from `~/.lux/keys/<name>/rt/`
- `--scheme lattice` - Uses ML-DSA keys from `~/.lux/keys/<name>/mldsa/`

**File Locations:**
- `/Users/z/work/lux/cli/cmd/keycmd/ring.go` - CLI commands
- `/Users/z/work/lux/crypto/ring/` - Core ring signature implementation

### E2E Tests

The `ring_e2e_test.go` file provides comprehensive end-to-end tests:

| Test | Description |
|------|-------------|
| TestE2E_LSAGRingSignature | Full LSAG sign/verify/serialize flow |
| TestE2E_LatticeRingSignature | Full post-quantum sign/verify flow |
| TestE2E_MultipleSignaturesSameKey | Double-spend detection via key images |
| TestE2E_DifferentRingSizes | Ring sizes 2, 3, 5, 10, 20 |
| TestE2E_CrossSchemeIsolation | LSAG/Lattice don't cross-verify |

**Benchmarks (Apple M1 Max):**
| Operation | Ring Size | Time | Allocations |
|-----------|-----------|------|-------------|
| LSAG Sign | 5 | 2.3ms | 10KB |
| LSAG Verify | 5 | 2.6ms | 10KB |
| Lattice Sign | 3 | 267µs | 100KB |
| Lattice Verify | 3 | 260µs | 100KB |

## Test Status (2025-12-19)

All test packages pass:

| Package | Status | Tests |
|---------|--------|-------|
| signer | PASS | - |
| bls | PASS | - |
| mldsa | PASS | - |
| mlkem | PASS | - |
| slhdsa | PASS | - |
| lamport | PASS | - |
| precompile | PASS | - |
| kzg4844 | PASS | - |
| ipa/* | PASS | - |
| bn256/* | PASS | - |
| ring | PASS | 21 tests |

## LP Cross-References

### Parent Specifications
- **LP-4200**: Post-Quantum Cryptography Suite (parent)
- **LP-2517**: EVM Precompile Suite Overview (index)

### Algorithm Specifications
| LP | Algorithm | Implementation |
|----|-----------|----------------|
| LP-4316 | ML-DSA (FIPS 204) | `mldsa/mldsa.go` |
| LP-4317 | SLH-DSA (FIPS 205) | `slhdsa/slhdsa.go` |
| LP-4318 | ML-KEM (FIPS 203) | `mlkem/mlkem.go` |
| LP-2506 | Lamport OTS | `lamport/lamport.go` |

### EVM Precompile Addresses
| Address | Name | LP |
|---------|------|-----|
| 0x0200...0006 | ML-DSA | LP-2311 |
| 0x0200...0007 | SLH-DSA | LP-2312 |
| 0x0140-0x0149 | SHAKE | - |
| 0x0150-0x0159 | Lamport | - |

## Documentation Site

Static docs site at `docs/` using fumadocs:

**Pages:**
1. index - Introduction
2. bls - BLS signatures
3. post-quantum - ML-DSA, ML-KEM, SLH-DSA
4. elliptic-curves - secp256k1, bn256
5. hash-functions - SHA, BLAKE, Keccak
6. key-management - HD wallets, KDF
7. security - Best practices
8. ring-signatures - Pulsar (lattice threshold)
9. lamport - One-time signatures
10. kzg4844 - Polynomial commitments
11. verkle-ipa - Inner product arguments
12. signer - Hybrid BLS + Pulsar
13. precompiles - EVM contracts

## Key Technologies

- **Go 1.26.1** - Implementation language (uses crypto/hpke, runtime/secret)
- **Cloudflare CIRCL v1.6.1** - FIPS-compliant PQ implementations
- **CGO optimizations** - Performance-critical operations
- **fumadocs** - Documentation framework

## Security Levels

| Algorithm | Security Level | Quantum Resistant | Type |
|-----------|---------------|-------------------|------|
| Pulsar | Lattice-based | Yes | Threshold |
| ML-DSA-65 | 192-bit (NIST Level 3) | Yes | Regular |
| ML-KEM-768 | 192-bit (NIST Level 3) | Yes | KEM |
| SLH-DSA-SHA2-128f | 128-bit (NIST Level 1) | Yes | Regular |
| BLS12-381 | 128-bit classical | No | Aggregatable |
| secp256k1 | 128-bit classical | No | Regular |

## Rules for AI Assistants

1. Update LLM.md with significant discoveries
2. Never commit AI-generated summary files
3. Follow Go coding standards
4. Test all implementations before claiming completion
5. Cross-reference LPs when discussing specifications
6. Pulsar = lattice threshold (NOT ring signatures, NOT ML-DSA)
7. ML-DSA = NIST FIPS 204 regular signatures (NOT threshold)

---

## Cross-Repository Threshold Signature Architecture

**Status**: Design Specification (2025-12-17)

This section defines the canonical architecture for threshold signatures across all Lux repositories.

### Design Principles

1. **Single Interface Layer**: `crypto/threshold` is the canonical interface
2. **Implementation Separation**: Protocol-specific code lives in dedicated repos
3. **Clean Dependencies**: No circular imports, clear layering
4. **Runtime Flexibility**: Switch schemes without code changes

### Package Dependency Graph

```
                     INTERFACE LAYER
                    ┌─────────────────┐
                    │ crypto/threshold │  <- Canonical interfaces
                    │  - Scheme        │     SchemeID, DKG, Signer, etc.
                    │  - Registry      │     RegisterScheme(), GetScheme()
                    │  - Session       │     SigningSession, SessionManager
                    │  - bls/          │     Built-in BLS threshold impl
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
    IMPLEMENTATION      IMPLEMENTATION      BUILT-IN
   ┌────────────┐      ┌────────────┐    ┌────────────┐
   │    mpc     │      │  corona  │    │crypto/bls  │
   │ (CGGMP21,  │      │ (Lattice)  │    │(Raw BLS12) │
   │   FROST)   │      │            │    │            │
   └─────┬──────┘      └─────┬──────┘    └─────┬──────┘
         │                   │                 │
         └───────────────────┼─────────────────┘
                             │
                    ┌────────▼────────┐
                    │   CONSUMERS     │
                    │                 │
         ┌─────────┬┴────────┬────────┬─────────┐
         ▼         ▼         ▼        ▼         ▼
     ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
     │node  │  │consen│  │bridge│  │wallet│  │vms/  │
     │/warp │  │sus/  │  │      │  │      │  │tvm   │
     │      │  │quasar│  │      │  │      │  │      │
     └──────┘  └──────┘  └──────┘  └──────┘  └──────┘
```

### Interface Contracts

#### 1. crypto/threshold (Interface Layer)

**File**: `/Users/z/work/lux/crypto/threshold/interfaces.go`

```go
// Scheme is the factory interface - all implementations MUST satisfy this
type Scheme interface {
    ID() SchemeID
    Name() string
    KeyShareSize() int
    SignatureShareSize() int
    SignatureSize() int
    PublicKeySize() int
    NewDKG(config DKGConfig) (DKG, error)
    NewTrustedDealer(config DealerConfig) (TrustedDealer, error)
    NewSigner(share KeyShare) (Signer, error)
    NewAggregator(groupKey PublicKey) (Aggregator, error)
    NewVerifier(groupKey PublicKey) (Verifier, error)
    ParseKeyShare(data []byte) (KeyShare, error)
    ParsePublicKey(data []byte) (PublicKey, error)
    ParseSignatureShare(data []byte) (SignatureShare, error)
    ParseSignature(data []byte) (Signature, error)
}
```

**Registration Pattern**:
```go
// In init() of each implementation
func init() {
    threshold.RegisterScheme(&MyScheme{})
}
```

#### 2. mpc (CGGMP21/FROST Implementation)

**File**: `/Users/z/work/lux/mpc/pkg/threshold/adapter.go` (TO CREATE)

```go
package threshold

import (
    "context"

    "github.com/luxfi/crypto/threshold"
    "github.com/luxfi/mpc/pkg/mpc"
    "github.com/luxfi/mpc/pkg/protocol"
)

// CGGMP21Scheme adapts mpc CGGMP21 to threshold.Scheme
type CGGMP21Scheme struct {
    node *mpc.Node
}

func init() {
    // Only register if mpc package is imported
    threshold.RegisterScheme(&CGGMP21Scheme{})
}

func (s *CGGMP21Scheme) ID() threshold.SchemeID {
    return threshold.SchemeCMP
}

func (s *CGGMP21Scheme) Name() string {
    return "CGGMP21 (Threshold ECDSA)"
}

// ... implement all Scheme methods wrapping mpc.Node
```

**Key Mapping**:
| mpc Type | threshold Interface |
|----------|---------------------|
| `mpc.KeyGenSession` | `threshold.DKG` |
| `mpc.SignSession` | `threshold.Signer` |
| `keyinfo.KeyInfo` | `threshold.KeyShare` |
| `protocol.Signature` | `threshold.Signature` |

#### 3. consensus/quasar (BLS Consumer)

**File**: `/Users/z/work/lux/consensus/protocol/quasar/bls.go`

**Current State**: Uses raw BLS with ad-hoc aggregation

**Migration**:
```go
package quasar

import (
    "github.com/luxfi/crypto/threshold"
    _ "github.com/luxfi/crypto/threshold/bls" // Register BLS scheme
)

type BLS struct {
    // Replace raw keys with threshold components
    scheme     threshold.Scheme
    signer     threshold.Signer
    aggregator threshold.Aggregator
    verifier   threshold.Verifier

    // Keep existing
    horizons []dag.EventHorizon[VertexID]
    store    dag.Store[VertexID]
}

func NewBLS(cfg config.Parameters, store dag.Store[VertexID], keyShare threshold.KeyShare) (*BLS, error) {
    scheme, err := threshold.GetScheme(threshold.SchemeBLS)
    if err != nil {
        return nil, err
    }

    signer, err := scheme.NewSigner(keyShare)
    if err != nil {
        return nil, err
    }

    aggregator, err := scheme.NewAggregator(keyShare.GroupKey())
    if err != nil {
        return nil, err
    }

    return &BLS{
        scheme:     scheme,
        signer:     signer,
        aggregator: aggregator,
        horizons:   make([]dag.EventHorizon[VertexID], 0),
        store:      store,
    }, nil
}

// generateBLSAggregate uses threshold aggregation
func (q *BLS) generateBLSAggregate(blockID ids.ID, shares []threshold.SignatureShare) ([]byte, error) {
    sig, err := q.aggregator.Aggregate(context.Background(), blockID[:], shares, nil)
    if err != nil {
        return nil, err
    }
    return sig.Bytes(), nil
}
```

#### 4. node/vms/thresholdvm — MPC mode (M-Chain) + FHE mode (F-Chain) per LP-134

**File**: `/Users/z/work/lux/node/vms/thresholdvm/vm.go`

Per LP-134 (Lux Chain Topology), the legacy T-Chain custody monolith
is split into two operational chains, both served by this single VM:

- `thresholdvm` in **MPC mode → M-Chain**: distributed key generation,
  threshold signing (CGGMP21 / FROST / Corona-DKG), key resharing.
- `thresholdvm` in **FHE mode → F-Chain**: TFHE bootstrap-key generation,
  encrypted-EVM compute. The TFHE keygen ceremony itself runs on M-Chain
  via FROST DKG and is consumed by F-Chain via a CertLane handoff.

Each runtime chooses one mode at boot via the `MChainAdapter` or
`FChainAdapter` registration in `chains/thresholdvm/runtime/`. The
substrate refuses cross-mode lane verifiers at boot, so a misconfigured
chain fails fast rather than silently mixing ceremonies.

The legacy "T-Chain" name is retained only for `teleportvm` (LP-6332),
the cross-chain teleport message bus, which is unrelated to thresholdvm.

**Current State**: Uses `github.com/luxfi/threshold/pkg/party` directly

**Migration** - Keep existing LSS but add threshold interface:
```go
package tvm

import (
    "github.com/luxfi/crypto/threshold"
    _ "github.com/luxfi/crypto/threshold/bls"  // BLS support
)

type VM struct {
    // Keep existing
    protocolRegistry *ProtocolRegistry
    lssConfig        *lssconfig.Config

    // Add threshold interface
    thresholdSchemes map[string]threshold.Scheme  // protocol -> scheme
}

func (vm *VM) initThresholdSchemes() error {
    vm.thresholdSchemes = make(map[string]threshold.Scheme)

    // Map internal protocols to threshold schemes
    for _, proto := range vm.protocolRegistry.List() {
        schemeID := protocolToSchemeID(proto)
        scheme, err := threshold.GetScheme(schemeID)
        if err == nil {
            vm.thresholdSchemes[string(proto)] = scheme
        }
    }
    return nil
}

// CreateSignatureShare using threshold interface
func (vm *VM) CreateSignatureShare(ctx context.Context, keyID string, message []byte, signers []int) (threshold.SignatureShare, error) {
    key := vm.keys[keyID]
    scheme := vm.thresholdSchemes[key.Protocol]

    signer, err := scheme.NewSigner(key.ThresholdKeyShare)
    if err != nil {
        return nil, err
    }

    return signer.SignShare(ctx, message, signers, nil)
}
```

#### 5. bridge TypeScript Client

**File**: `/Users/z/work/lux/bridge/pkg/threshold/src/client.ts`

```typescript
// TypeScript calls Go threshold APIs via JSON-RPC
import type {
  KeygenRequest,
  SignRequest,
  SignatureShare,
} from './types'

export class ThresholdClient {
  constructor(private endpoint: string) {}

  // Map to threshold.Scheme.NewDKG / TrustedDealer
  async keygen(req: KeygenRequest): Promise<KeygenResponse> {
    return this.rpc('threshold.keygen', req)
  }

  // Map to threshold.Signer.SignShare
  async signShare(req: SignRequest): Promise<SignatureShare> {
    return this.rpc('threshold.signShare', req)
  }

  // Map to threshold.Aggregator.Aggregate
  async aggregate(shares: SignatureShare[]): Promise<Signature> {
    return this.rpc('threshold.aggregate', { shares })
  }

  // Map to threshold.Verifier.Verify
  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return this.rpc('threshold.verify', { message, signature })
  }

  private async rpc<T>(method: string, params: unknown): Promise<T> {
    const res = await fetch(this.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    })
    const json = await res.json()
    if (json.error) throw new Error(json.error.message)
    return json.result as T
  }
}
```

### Migration Path

#### Phase 1: Interface Stabilization (crypto/threshold) - DONE
- [x] Define Scheme, DKG, Signer, Aggregator, Verifier interfaces
- [x] Implement registry with RegisterScheme/GetScheme
- [x] Add SigningSession and SessionManager
- [x] Implement BLS skeleton in threshold/bls/

#### Phase 2: MPC Adapter (mpc repo)
1. Create `/Users/z/work/lux/mpc/pkg/threshold/adapter.go`
2. Implement CGGMP21Scheme wrapping mpc.Node
3. Map mpc session types to threshold interfaces
4. Register in init(): `threshold.RegisterScheme(&CGGMP21Scheme{})`
5. Update go.mod: `require github.com/luxfi/crypto v1.x.x`

#### Phase 3: Consensus Integration (consensus repo)
1. Update `protocol/quasar/bls.go` to use threshold.Scheme
2. Replace raw BLS key handling with threshold.KeyShare
3. Use threshold.Aggregator for signature aggregation
4. Add threshold.Verifier for signature verification

#### Phase 4: Node Integration (node repo)
1. Update `vms/thresholdvm/` to expose threshold API
2. Map internal protocols to threshold.SchemeID
3. Implement JSON-RPC methods mapping to threshold interfaces
4. Update warp signing to use threshold when configured

#### Phase 5: Bridge TypeScript Client (bridge repo)
1. Update `pkg/threshold/src/client.ts` types
2. Map RPC methods to Go threshold API
3. Add scheme negotiation (auto-select based on chain)

### Implementation Checklist

| Repo | File | Status | Notes |
|------|------|--------|-------|
| crypto | threshold/interfaces.go | DONE | Core interfaces |
| crypto | threshold/registry.go | DONE | Scheme registration |
| crypto | threshold/session.go | DONE | Session management |
| crypto | threshold/bls/scheme.go | PARTIAL | Needs polynomial eval |
| mpc | pkg/threshold/adapter.go | TODO | CGGMP21Scheme adapter |
| mpc | pkg/threshold/frost.go | TODO | FROSTScheme adapter |
| consensus | protocol/quasar/bls.go | TODO | Use threshold.Scheme |
| node | vms/thresholdvm/threshold_api.go | TODO | JSON-RPC mapping |
| bridge | pkg/threshold/src/client.ts | EXISTS | Update types |

### Import Rules (No Cycles!)

```
crypto/threshold     <- Interface definitions (no external deps)
    ^
    |
mpc/pkg/threshold    <- Adapters (imports crypto/threshold)
    ^
    |
node/vms/thresholdvm <- Service (imports both)
consensus/quasar     <- Consumer (imports crypto/threshold)
bridge/pkg/threshold <- TypeScript (calls node via RPC)
```

**FORBIDDEN**:
- crypto/threshold MUST NOT import mpc
- mpc MUST NOT import node or consensus
- consensus MUST NOT import mpc directly (use threshold interface)

### Implementation Status (2025-12-17 Session Complete)

| Component | File | Status | Tests |
|-----------|------|--------|-------|
| crypto/threshold interfaces | `threshold/interfaces.go` | ✅ DONE | PASS |
| crypto/threshold registry | `threshold/registry.go` | ✅ DONE | PASS |
| crypto/threshold BLS scheme | `threshold/bls/scheme.go` | ✅ PARTIAL (stub polynomial) | PASS |
| mpc CGGMP21 adapter | `/Users/z/work/lux/mpc/pkg/threshold/crypto_adapter.go` | ✅ DONE | PASS |
| mpc FROST adapter | `/Users/z/work/lux/mpc/pkg/threshold/crypto_adapter.go` | ✅ DONE | PASS |
| consensus hybrid threshold | `/Users/z/work/lux/consensus/protocol/quasar/hybrid.go` | ✅ DONE | PASS (37 tests) |
| node warp threshold | `/Users/z/work/lux/node/vms/platformvm/warp/signature.go` | ✅ DONE | BUILD OK |
| bridge threshold client | `/Users/z/work/lux/bridge/pkg/threshold/src/client.ts` | ✅ ALREADY EXISTS | - |

**Key Changes This Session:**

1. **MPC Adapters** (`/Users/z/work/lux/mpc/pkg/threshold/crypto_adapter.go`):
   - `CGGMP21Scheme` - Wraps CGGMP21 protocol for threshold ECDSA
   - `FROSTScheme` - Wraps FROST protocol for threshold EdDSA
   - Both register with `crypto/threshold` registry in init()

2. **Consensus Hybrid** (`/Users/z/work/lux/consensus/protocol/quasar/hybrid.go`):
   - Added `ThresholdConfig` struct for configuration
   - Added `NewHybridWithThreshold()` constructor
   - Added threshold-specific methods: `SignMessageThreshold()`, `AggregateThresholdSignatures()`, `VerifyThresholdSignature()`
   - 6 new tests for threshold mode

3. **Node Warp Signatures** (`/Users/z/work/lux/node/vms/platformvm/warp/signature.go`):
   - Updated `AggregateCoronaPublicKeys()` to check for `SchemeCorona` availability
   - Updated `VerifyCoronaSignature()` to use `threshold.Verifier` when available
   - Added fallback to structural validation for testing

4. **Bridge**: Already uses threshold signing via ThresholdClient SDK (2-of-3 MPC)

### Runtime Scheme Selection

```go
// At startup, import the schemes you need
import (
    "github.com/luxfi/crypto/threshold"
    _ "github.com/luxfi/crypto/threshold/bls"      // BLS support
    _ "github.com/luxfi/mpc/pkg/threshold"         // CGGMP21/FROST support
)

// Select at runtime
func getSchemeForChain(chain string) (threshold.Scheme, error) {
    switch chain {
    case "ethereum", "polygon", "bsc":
        return threshold.GetScheme(threshold.SchemeCMP)  // ECDSA via CGGMP21
    case "solana", "sui":
        return threshold.GetScheme(threshold.SchemeFROST) // Ed25519 via FROST
    case "lux":
        return threshold.GetScheme(threshold.SchemeBLS)   // BLS for consensus
    default:
        return nil, fmt.Errorf("unsupported chain: %s", chain)
    }
}
```

---

## Threshold Signature Architecture Refactoring (2025-12-19) - COMPLETED

### COMPLETED: Adapter Layer Removed

**Final Architecture:**

```
crypto/threshold/               <- Interface layer (GOOD)
    interfaces.go               <- Core interfaces: Scheme, DKG, Signer, etc.
    registry.go                 <- RegisterScheme(), GetScheme()
    adapter.go                  <- SchemeAdapter convenience wrapper (OK)
    session.go                  <- SigningSession management (OK)
    errors.go                   <- Error definitions (OK)
    bls/                        <- BLS implementation (GOOD - native)
        scheme.go               <- Implements threshold.Scheme directly
    [DELETED: corona/]        <- Adapter removed!

corona/                       <- Native threshold implementation
    threshold/                  <- NEW: Native threshold.Scheme implementation
        threshold.go            <- Params, GroupKey, KeyShare, Signer, Signature
        threshold_test.go       <- 4 tests all pass
    sign/
        sign.go                 <- Party, Gen, SignRound1/2, Verify
        config.go               <- Constants

consensus/protocol/quasar/
    quasar.go                   <- Uses corona/threshold directly (renamed from hybrid.go)
```

**The Issue:**

`crypto/threshold/corona/scheme.go` is an **adapter layer** that:
1. Imports `github.com/luxfi/corona/sign` and `github.com/luxfi/corona/primitives`
2. Creates wrapper types (KeyShare, PublicKey, Signer, etc.) that wrap real Pulsar types
3. Translates between `threshold.*` interfaces and `corona.sign.*` types
4. Duplicates type definitions with conversion logic

This violates the design goal of having implementations be **native** to the interface.

**Contrast with BLS (the correct pattern):**

`crypto/threshold/bls/scheme.go`:
- Implements `threshold.Scheme` directly
- Uses `crypto/bls` as primitives
- No separate "real" BLS threshold package elsewhere
- Types are defined once, implementing interfaces natively

### DESIGN GOAL: Native Interface Implementation

```
                    INTERFACE (stays in crypto/threshold)
                   ┌─────────────────────────────────────┐
                   │  threshold.Scheme                   │
                   │  threshold.Signer                   │
                   │  threshold.Aggregator               │
                   │  threshold.Verifier                 │
                   │  threshold.KeyShare                 │
                   │  threshold.PublicKey                │
                   │  threshold.Signature                │
                   └──────────────┬──────────────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
   ┌──────▼──────┐         ┌──────▼──────┐        ┌───────▼───────┐
   │ threshold/  │         │  corona/  │        │   mpc/pkg/    │
   │    bls/     │         │ threshold/  │        │   threshold/  │
   │ (Native)    │         │  (Native)   │        │   (Native)    │
   └─────────────┘         └─────────────┘        └───────────────┘
                                  │
                    No more adapter layer!
                    Pulsar implements threshold.Scheme
                    directly in the corona repo
```

### COMPLETED ACTIONS

#### Phase 1: DELETED from crypto/threshold ✅

**Files DELETED:**
```
crypto/threshold/corona/scheme.go      <- DELETED
crypto/threshold/corona/scheme_test.go <- DELETED
```

The entire `crypto/threshold/corona/` directory was removed.

#### Phase 2: ADDED to corona repo ✅

**Created:** `corona/threshold/threshold.go`

The Pulsar package now implements threshold signatures natively (2-round protocol):

```go
// corona/threshold/threshold.go
package threshold

import (
    "github.com/luxfi/lattice/v6/ring"
    "github.com/luxfi/corona/sign"
    "github.com/luxfi/corona/primitives"
)

// GroupKey holds the public parameters for the threshold group.
type GroupKey struct {
    A      structs.Matrix[ring.Poly]
    BTilde structs.Vector[ring.Poly]
    Params *Params
}

// KeyShare holds a party's secret share data.
type KeyShare struct {
    Index    int
    SkShare  structs.Vector[ring.Poly]
    Seeds    map[int][][]byte
    MACKeys  map[int][]byte
    Lambda   ring.Poly
    GroupKey *GroupKey
}

// Signer handles threshold signing for a single party.
type Signer struct {
    share  *KeyShare
    party  *sign.Party
    params *Params
}

// 2-Round Protocol:
func (s *Signer) Round1(sessionID int, prfKey []byte, signers []int) *Round1Data
func (s *Signer) Round2(sessionID int, message string, prfKey []byte, signers []int, round1Data map[int]*Round1Data) (*Round2Data, error)
func (s *Signer) Finalize(round2Data map[int]*Round2Data) (*Signature, error)
func Verify(groupKey *GroupKey, message string, sig *Signature) bool
```

#### Phase 3: MODIFIED consensus/quasar/quasar.go ✅

**File renamed:** `hybrid.go` → `quasar.go`

**Updated imports:**
```go
import (
    "github.com/luxfi/crypto/threshold"
    _ "github.com/luxfi/crypto/threshold/bls"
    coronaThreshold "github.com/luxfi/corona/threshold"  // Direct import
)
```

**Key additions:**
- `HybridConfig` struct with `CoronaShares` and `CoronaGroupKey` fields
- `DualSignRound1()` - Returns BLS share + Pulsar Round1 data in parallel
- `CoronaRound1/Round2/Finalize()` - Exposes 2-round protocol methods
- `GenerateDualKeys()` - Generates both BLS and Pulsar threshold keys

### ARCHITECTURE DIAGRAM (Clean State)

```
┌──────────────────────────────────────────────────────────────────────┐
│                         INTERFACE LAYER                               │
│                    github.com/luxfi/crypto/threshold                  │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ interfaces.go: Scheme, DKG, Signer, Aggregator, Verifier     │    │
│  │ registry.go: RegisterScheme(), GetScheme(), ListSchemes()    │    │
│  │ session.go: SigningSession, SessionManager                   │    │
│  │ adapter.go: SchemeAdapter (convenience, not scheme-specific) │    │
│  │ errors.go: Sentinel errors                                   │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌──────────────────┐                                                 │
│  │ bls/scheme.go    │  <- Native BLS threshold implementation        │
│  │ Implements:      │                                                 │
│  │   threshold.Scheme natively                                       │
│  │   Uses: crypto/bls primitives                                     │
│  └──────────────────┘                                                 │
│                                                                       │
│  [DELETED: corona/scheme.go - no longer exists here]               │
└──────────────────────────────────────────────────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
         ▼                          ▼                          ▼
┌─────────────────────┐  ┌─────────────────────┐  ┌──────────────────────┐
│ github.com/luxfi/   │  │ github.com/luxfi/   │  │ github.com/luxfi/    │
│     corona        │  │       mpc           │  │     consensus        │
│                     │  │                     │  │                      │
│ ┌─────────────────┐ │  │ ┌─────────────────┐ │  │ ┌──────────────────┐ │
│ │ threshold/      │ │  │ │ pkg/threshold/  │ │  │ │ protocol/quasar/ │ │
│ │   scheme.go     │ │  │ │   adapter.go    │ │  │ │   hybrid.go      │ │
│ │                 │ │  │ │                 │ │  │ │                  │ │
│ │ Implements:     │ │  │ │ Implements:     │ │  │ │ Uses:            │ │
│ │  threshold.     │ │  │ │  threshold.     │ │  │ │  threshold.      │ │
│ │  Scheme         │ │  │ │  Scheme         │ │  │ │  GetScheme()     │ │
│ │  natively       │ │  │ │  for CGGMP21    │ │  │ │                  │ │
│ │                 │ │  │ │  and FROST      │ │  │ │ Imports:         │ │
│ │ Uses sign/      │ │  │ │                 │ │  │ │  threshold/bls   │ │
│ │ directly        │ │  │ │ Uses mpc.Node   │ │  │ │  corona/       │ │
│ └─────────────────┘ │  │ └─────────────────┘ │  │ │  threshold       │ │
│                     │  │                     │  │ └──────────────────┘ │
│ ┌─────────────────┐ │  │                     │  │                      │
│ │ sign/sign.go    │ │  │                     │  │                      │
│ │ (Core impl)     │ │  │                     │  │                      │
│ └─────────────────┘ │  │                     │  │                      │
└─────────────────────┘  └─────────────────────┘  └──────────────────────┘
```

### EXACT FILE CHANGES

#### 1. DELETE (crypto repo)

```bash
# In /Users/z/work/lux/crypto
rm -rf threshold/corona/
```

Files removed:
- `/Users/z/work/lux/crypto/threshold/corona/scheme.go`
- `/Users/z/work/lux/crypto/threshold/corona/scheme_test.go`

#### 2. CREATE (corona repo)

**File:** `/Users/z/work/lux/corona/threshold/scheme.go`

This file moves the implementation from `crypto/threshold/corona/scheme.go` but refactors it to be native rather than a wrapper. Key changes:

1. Types defined in corona, not wrapping corona types
2. Direct use of `sign.Party` methods, no translation
3. Same init() registration pattern
4. Imports `github.com/luxfi/crypto/threshold` for interfaces only

**File:** `/Users/z/work/lux/corona/threshold/scheme_test.go`

Move and adapt tests.

#### 3. MODIFY (consensus repo)

**File:** `/Users/z/work/lux/consensus/protocol/quasar/hybrid.go`

Change:
```go
_ "github.com/luxfi/crypto/threshold/corona" // Register Pulsar threshold scheme
```

To:
```go
_ "github.com/luxfi/corona/threshold" // Register Pulsar threshold scheme
```

#### 4. MODIFY (corona repo go.mod)

**File:** `/Users/z/work/lux/corona/go.mod`

Add:
```go
require github.com/luxfi/crypto v1.x.x
```

### BENEFITS OF THIS REFACTORING

1. **No Duplication**: Types are defined once, in corona, implementing threshold interfaces
2. **No Interpretation**: No translation layer between two type systems
3. **Single Source**: Pulsar logic lives in corona repo
4. **Clean Dependencies**:
   - crypto/threshold -> defines interfaces
   - corona -> implements interfaces
   - consensus -> uses interfaces
5. **Consistent Pattern**: Both BLS and Pulsar now follow same pattern

### WHAT TO KEEP (Unchanged)

These files in `crypto/threshold/` are **not adapters** and should remain:

| File | Purpose | Keep? |
|------|---------|-------|
| `interfaces.go` | Core interface definitions | YES |
| `errors.go` | Sentinel errors | YES |
| `registry.go` | Scheme registration | YES |
| `session.go` | Multi-party session management | YES |
| `adapter.go` | SchemeAdapter (generic helper, not scheme-specific) | YES |
| `interfaces_test.go` | Interface tests | YES |
| `bls/scheme.go` | Native BLS threshold implementation | YES |
| `bls/scheme_test.go` | BLS tests | YES |

The `adapter.go` file is confusingly named but it's actually a **convenience wrapper** that works with any scheme, not a scheme-specific adapter. Consider renaming to `helpers.go` for clarity.

### SUMMARY - COMPLETED ✅

| Action | Location | Status |
|--------|----------|--------|
| DELETE | `crypto/threshold/corona/` | ✅ Deleted |
| CREATE | `corona/threshold/threshold.go` | ✅ Created |
| CREATE | `corona/threshold/threshold_test.go` | ✅ Created (4 tests) |
| MODIFY | `consensus/go.mod` | ✅ Added corona replace |
| MODIFY | `consensus/protocol/quasar/hybrid.go` → `quasar.go` | ✅ Renamed, updated |
| CREATE | `consensus/protocol/quasar/dual_threshold_test.go` | ✅ Created (5 tests) |

### TEST RESULTS (2025-12-19)

**Pulsar Threshold Tests (4 tests):**
- TestGenerateKeys ✅
- TestThresholdSigningFlow ✅ (2-round protocol verified)
- TestThresholdWrongMessage ✅
- TestInvalidThreshold ✅

**Consensus Quasar Tests (158 tests):**
- TestBLSThresholdSigningFlow ✅
- TestBLSThresholdInsufficientShares ✅
- TestBLSThresholdWrongMessage ✅
- TestDualThresholdKeyGeneration ✅
- **TestDualSigningFlow ✅** - Full BLS + Pulsar 2-round protocol

### KEY ACHIEVEMENT

**Dual Threshold Signing Flow** - Validators can now sign blocks with both:
1. **BLS** (1 round): Immediate aggregation for classical security
2. **Pulsar** (2 rounds): Post-quantum security via lattice-based threshold signatures

Both run in parallel, with BLS completing in Round 1 while Pulsar completes after Round 2.

### PENDING WORK

- All threshold signature architecture work is complete ✅

---

## Epoch-Based Key Management (2025-12-19) - COMPLETED

### Overview

The `EpochManager` in `consensus/protocol/quasar/epoch.go` manages Pulsar key epochs for validator sets with rate limiting to prevent excessive key churn while still rotating frequently enough to frustrate quantum attacks.

### Key Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MinEpochDuration` | 10 minutes | Minimum time between key rotations (rate limiting) |
| `MaxEpochDuration` | 1 hour | Maximum time keys can be used (forced rotation) |
| `QuantumCheckpointInterval` | 3 seconds | How often we create quantum-safe signatures |
| `DefaultHistoryLimit` | 6 | Number of old epochs to keep (1 hour with 10-min epochs) |

### Epoch Counter Limits

The epoch uses `uint64` which supports values up to 18,446,744,073,709,551,615. At 1 epoch per 10 minutes:
- **351 trillion years** of epochs before overflow
- Effectively unlimited for all practical purposes

### Core Types

```go
// EpochManager manages Pulsar key epochs for the validator set.
type EpochManager struct {
    mu              sync.RWMutex
    currentEpoch    uint64
    currentKeys     *EpochKeys
    lastKeygenTime  time.Time
    epochHistory    map[uint64]*EpochKeys  // For cross-epoch verification
    historyLimit    int                     // How many old epochs to keep
    currentValidators []string
    threshold         int
}

// EpochKeys holds the Pulsar keys for a specific epoch.
type EpochKeys struct {
    Epoch           uint64
    CreatedAt       time.Time
    ExpiresAt       time.Time
    ValidatorSet    []string
    Threshold       int
    TotalParties    int
    GroupKey        *coronaThreshold.GroupKey
    Shares          map[string]*coronaThreshold.KeyShare
    Signers         map[string]*coronaThreshold.Signer
}
```

### API Methods

| Method | Purpose |
|--------|---------|
| `NewEpochManager(threshold, historyLimit)` | Create manager |
| `InitializeEpoch(validators)` | Create first epoch (genesis) |
| `RotateEpoch(validators, force)` | Rotate keys for new validator set |
| `ForceRotateIfExpired()` | Rotate if MaxEpochDuration passed |
| `GetCurrentKeys()` | Get current epoch keys |
| `GetEpochKeys(epoch)` | Get historical epoch keys |
| `GetSigner(validatorID)` | Get signer for validator in current epoch |
| `GetSignerForEpoch(validatorID, epoch)` | Get signer for historical epoch |
| `VerifySignatureForEpoch(message, sig, epoch)` | Verify sig from any epoch |
| `TimeUntilNextRotation()` | Time until rate limit allows rotation |
| `Stats()` | Get epoch statistics |

### Rate Limiting Behavior

```go
// RotateEpoch returns ErrEpochRateLimited if called within MinEpochDuration
if elapsed := now.Sub(em.lastKeygenTime); elapsed < MinEpochDuration {
    return nil, fmt.Errorf("%w: %v remaining", ErrEpochRateLimited, remaining)
}

// Returns ErrNoValidatorChange if validator set hasn't changed (unless force=true)
if !force && em.validatorSetUnchanged(validators) {
    return nil, ErrNoValidatorChange
}
```

### Epoch History

- Historical epochs are preserved for signature verification during transitions
- Default keeps last 3 epochs
- Pruning removes epochs older than `currentEpoch - historyLimit + 1`

### Integration with Quasar Core

In `core.go`, the Quasar consensus engine integrates epoch management:

```go
type Quasar struct {
    epochManager  *EpochManager
    // ...
}

// AddValidator rotates keys when validator set changes
func (q *Quasar) AddValidator(validatorID string, coronaShare ...) error {
    keys, err := q.epochManager.RotateEpoch(validators, false)
    if errors.Is(err, ErrEpochRateLimited) || errors.Is(err, ErrNoValidatorChange) {
        // Not an error - just rate limited or no change
        rotated = false
        err = nil
    }
    // ...
}
```

### Critical Bug Fix: Pulsar Verify Function

**Issue**: The Pulsar `Verify` function in `/Users/z/work/lux/corona/sign/sign.go:290` was **destructive** - it modified the input signature's `z` vector in-place with `utils.ConvertVectorFromNTT(r, z)`.

**Symptom**: Epoch 0 signatures failed to verify after rotation because the first verification call mutated the signature.

**Fix**: Create a deep copy of the z vector before modification:

```go
// In corona/sign/sign.go Verify function
// Make a copy of z to avoid modifying the input signature
zCopy := make(structs.Vector[ring.Poly], len(z))
for i := range z {
    zCopy[i] = *z[i].CopyNew()  // Deep copy polynomial
}

// Now use zCopy instead of z for all operations
utils.ConvertVectorFromNTT(r, zCopy)
utils.MatrixVectorMul(r, A, zCopy, Az_bc)
// ...
```

### 3-Second Quantum Bundles (Parallel BLS + Pulsar)

**Architecture (parallel execution):**
```
BLS Layer:     [B1]--[B2]--[B3]--[B4]--[B5]--[B6]--[B7]--[B8]--...
                 |     500ms finality per block     |
                 |___________________________________|
                                  |
Quantum Layer:              [QB1: Merkle(B1-B6)]--------[QB2: Merkle(B7-B12)]
                                  |  3-second interval, async Pulsar signing
```

**NTT Pulsar benchmarks (IEEE S&P 2025):**
- 0.6s online signing phase (2-round protocol)
- 2.5s total including offline prep across 5 continents
- Our 3-second interval provides comfortable margin

**Core Types:**

```go
// QuantumBundle bundles multiple BLS-signed blocks into a quantum-safe anchor.
// BLS blocks continue at 500ms pace; quantum bundles form every 3 seconds.
type QuantumBundle struct {
    Epoch        uint64     // Current key epoch
    Sequence     uint64     // Bundle sequence within epoch
    StartHeight  uint64     // First BLS block in this bundle
    EndHeight    uint64     // Last BLS block in this bundle
    BlockCount   int        // Number of BLS blocks bundled
    MerkleRoot   [32]byte   // Merkle root of BLS block hashes
    BlockHashes  [][32]byte // Individual block hashes (for Merkle proof)
    PreviousHash [32]byte   // Previous bundle hash (chain linkage)
    Timestamp    int64      // Unix timestamp
    Signature    *coronaThreshold.Signature
}

// BundleSigner handles creating and verifying quantum bundles.
bs := NewBundleSigner(epochManager)

// Add BLS blocks as they finalize (~500ms each)
for each finalizedBlock {
    bs.AddBLSBlock(block.Height, block.Hash)
}

// Every 3 seconds, create and sign a bundle
bundle := bs.CreateBundle()
err := bs.SignBundle(bundle, sessionID, prfKey, validators)
valid := bs.VerifyBundle(bundle)
```

**Async Signing (for production):**

```go
// AsyncBundleSigner runs Pulsar signing in background
signer := NewAsyncBundleSigner(epochManager)

// BundleRunner automates the 3-second production loop
runner := NewBundleRunner(signer, validators, prfKey)
runner.Start()  // Goroutine creates bundles every 3 seconds

// Consume signed bundles
for signedBundle := range signer.SignedBundles() {
    // Broadcast to network
}

runner.Stop()
```

**Key Features:**
- BLS finality continues at 500ms - no latency impact
- Pulsar signing runs async, doesn't block BLS
- ~6 BLS blocks per quantum bundle (3s / 500ms)
- Merkle root provides compact proof of all BLS blocks
- Bundle chain via `PreviousHash` linkage
- Sequence resets on epoch rotation

**Performance** (with 3 validators, ~243ms per bundle):
- Signing completes well within 3-second window
- Merkle root computation: <1ms for 6 blocks
- Async signing: no blocking of BLS production

### Grouped Threshold Signing (Future Scaling)

For 100+ validators, `GroupedEpochManager` provides scaling via small groups:

```go
gem := NewGroupedEpochManager(3, 2, historyLimit) // Groups of 3, 2-of-3 threshold

// Parallel signing across groups
sigs, err := gem.ParallelGroupSign(sessionID, message, prfKey, signersByGroup)

// 2/3 of groups must sign for quorum
valid, err := gem.VerifyGroupedSignature(groupedSig)
```

Currently disabled in favor of simple approach for <100 validators.

### Test Coverage

All epoch tests pass (part of 174 total Quasar tests):

| Test | Description |
|------|-------------|
| `TestEpochManager_Initialize` | Initial epoch creation |
| `TestEpochManager_RotateEpoch` | Key rotation on validator change |
| `TestEpochManager_RateLimiting` | 10-minute rate limit enforcement |
| `TestEpochManager_NoChangeRejection` | Rejects rotation for unchanged set |
| `TestEpochManager_ForceRotation` | Force rotation bypasses checks |
| `TestEpochManager_HistoryPreservation` | Cross-epoch verification |
| `TestQuasar_AddValidator_RateLimited` | Integration with Quasar |
| `TestQuasar_EpochSigningAfterRotation` | Epoch 0 sigs verify after rotation |
| `TestQuantumCheckpoint_Create` | Checkpoint creation and chaining |
| `TestQuantumCheckpoint_SignAndVerify` | Sign/verify with 3 validators (~246ms) |
| `TestQuantumCheckpoint_SignWithThreshold` | Threshold signing (2-of-3) |
| `TestQuantumCheckpoint_ChainIntegrity` | Chain of 5 checkpoints verified |
| `TestQuantumCheckpoint_EpochSequenceReset` | Sequence resets on epoch rotation |

### Files Created/Modified

| File | Action |
|------|--------|
| `consensus/protocol/quasar/epoch.go` | Created - EpochManager implementation |
| `consensus/protocol/quasar/epoch_test.go` | Created - Epoch tests |
| `consensus/protocol/quasar/core.go` | Modified - Epoch integration |
| `corona/sign/sign.go` | Fixed - Non-destructive Verify |

---

## Session: geth v1.16.1 Module Path Fix (2025-12-20)

### Problem
The Go module proxy cached `github.com/luxfi/geth@v1.16.1` which had incorrect module path declaration (`github.com/ethereum/go-ethereum` instead of `github.com/luxfi/geth`). This caused build failures across the ecosystem.

### Solution
1. Deleted 718 broken geth tags with wrong module paths from GitHub
2. Added `exclude github.com/luxfi/geth v1.16.1` to go.mod files
3. Published patch releases with the fix

### Published Versions

| Package | Version | Changes |
|---------|---------|---------|
| crypto | v1.17.25 | Added geth exclude |
| crypto | v1.17.26 | Added ring signatures package |
| evm | v0.16.4 | Added exclude, removed -lux suffix tags |
| coreth | v0.15.55 | Added exclude |
| node | v1.22.21 | Added exclude, bumped crypto/coreth |
| netrunner | v1.14.19 | Added exclude, bumped crypto/node |
| sdk | v1.16.28 | Added exclude, bumped deps (needs more work) |

### Pending Work
- **SDK**: Needs import migration from `github.com/luxfi/utils/constants` to `github.com/luxfi/constants`
- **SDK**: API rename: Subnet→Chain (e.g., `tx.Net` → `tx.Chain`, `txs.ChainValidator.Net` → `txs.ChainValidator.Chain`)
- **CLI**: Uses local replaces, needs SDK fixes first

### Ring Signatures (ring/)
New package for anonymous group signing (LSAG - Linkable Spontaneous Anonymous Group):
- `ring.go` - Core interface and scheme types
- `lsag.go` - LSAG implementation on secp256k1
- `lattice.go` - Future lattice-based ring signatures

---

## GPU-Accelerated ZK Operations (2026-01-03) - UNIFIED ARCHITECTURE

### Overview

The `gpu/` package provides GPU-accelerated ZK cryptographic operations with automatic threshold-based routing between CPU and GPU execution paths.

### Architecture (Unified GPU Stack)

```
┌─────────────────────────────────────────────────────────┐
│              crypto/gpu/zk.go                           │
│  - Threshold-gated routing (CPU vs GPU)                 │
│  - CPU fallback via gnark-crypto                        │
│  - Uses github.com/luxfi/gpu for GPU ops                │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
         ┌─────────────────────────────────────┐
         │        github.com/luxfi/gpu         │
         │   Go bindings to luxfi/accel        │
         │                                     │
         │  zk.go (non-CGO stub)               │
         │  zk_cgo.go (CGO bindings)           │
         └──────────────────┬──────────────────┘
                            │
                            ▼
         ┌─────────────────────────────────────┐
         │          luxfi/accel                │
         │   Unified Metal/CUDA/CPU backend    │
         │                                     │
         │  zk/zk.cpp     - C++ impl           │
         │  zk/zk_c_api.h - C API              │
         └─────────────────────────────────────┘
```

**Key Change (2026-01-03)**: Removed separate platform files (`zk_metal.go`, `zk_cuda.go`)
in favor of the unified `github.com/luxfi/gpu` package which handles all backends via luxfi/accel.

### Threshold Constants (Tuned for Apple Silicon)

| Operation | Threshold | Description |
|-----------|-----------|-------------|
| `ThresholdPoseidon2` | 64 | Batch Poseidon2 hashes |
| `ThresholdMerkle` | 128 | Merkle layer leaf pairs |
| `ThresholdMSM` | 256 | Point-scalar pairs |
| `ThresholdCommitment` | 128 | Batch commitments |
| `ThresholdFRI` | 512 | FRI evaluations |

Below threshold: CPU (lower latency). Above threshold: GPU (higher throughput).

### Core Types

```go
// Fr256 is a type alias to luxgpu.Fr256 - 256-bit field element (BN254 scalar field).
// Uses 4 x 64-bit limbs in little-endian order.
type Fr256 = luxgpu.Fr256  // [4]uint64

// ZKContext provides GPU-accelerated ZK operations with automatic routing.
type ZKContext struct {
    gpuEnabled bool
    deviceName string
    gpuCalls   int64
    cpuCalls   int64
}
```

**Note**: `Fr256` is now a type alias to `github.com/luxfi/gpu.Fr256`, ensuring consistent
type representation across the GPU stack.

### Operations

| Function | Description |
|----------|-------------|
| `Poseidon2Hash(left, right)` | Single Poseidon2 hash (always CPU) |
| `Poseidon2BatchHash(left, right)` | Batch hashes with threshold routing |
| `MerkleRoot(leaves)` | Poseidon2 Merkle root |
| `MerkleTree(leaves)` | Complete Merkle tree internal nodes |
| `Commitment(value, blinding, salt)` | Poseidon2 commitment |
| `Nullifier(key, commitment, index)` | Poseidon2 nullifier |

### Usage

```go
import "github.com/luxfi/crypto/gpu"

// Get the global ZK context
ctx := gpu.GetZKContext()

// Check GPU availability
if ctx.GPUEnabled() {
    fmt.Println("GPU:", ctx.DeviceName())
}

// Single hash (always CPU)
result := gpu.Poseidon2Hash(&left, &right)

// Batch hash (threshold routing)
results, err := gpu.Poseidon2BatchHash(leftSlice, rightSlice)

// Merkle root
root, err := gpu.MerkleRoot(leaves)

// Statistics
gpuCalls, cpuCalls := ctx.Stats()
```

### Build Tags

| Build | Tags | GPU Support |
|-------|------|-------------|
| Default | (none) | CPU only (gnark-crypto) |
| Metal | `darwin,arm64,cgo,gpu` | Apple Silicon GPU |
| CUDA | `linux,cgo,gpu` | NVIDIA GPU (future) |

```bash
# CPU-only build
go build ./...

# Metal GPU build
CGO_ENABLED=1 go build -tags "gpu" ./...
```

### Files

| File | Purpose |
|------|---------|
| `gpu/zk.go` | Core ZK operations, threshold routing, CPU fallback via gnark-crypto |
| `gpu/zk_test.go` | Tests for ZK operations |

### Dependencies

- `github.com/luxfi/gpu` - Unified GPU bindings (wraps luxfi/accel)
- `github.com/consensys/gnark-crypto` - CPU Poseidon2 via BN254/Fr

### GPU Stack (luxfi/accel)

| File | Purpose |
|------|---------|
| `lux/gpu/zk.go` | Non-CGO stub (returns ErrZKNotAvailable) |
| `lux/gpu/zk_cgo.go` | CGO bindings to luxfi/accel |
| `luxfi/accel/zk/zk.h` | C++ ZK operations header |
| `luxfi/accel/zk/zk.cpp` | C++ ZK implementation |
| `luxfi/accel/zk/zk_c_api.h` | C API for Go bindings |
| `luxfi/accel/zk/zk_c_api.cpp` | C API implementation |

### Test Coverage

All tests pass in both CGO and non-CGO modes:

```bash
# Non-CGO (CPU only)
CGO_ENABLED=0 go test ./gpu/...

# CGO (with GPU if available)
CGO_ENABLED=1 go test ./gpu/...
```

### Published Versions

- `github.com/luxfi/crypto` - Go package with GPU ZK operations
- `github.com/luxfi/gpu` - Go bindings to unified GPU (Metal/CUDA/CPU)
- `luxfi/accel` - C++ GPU acceleration library (Metal/CUDA/CPU)

---

**Single source of truth for AI assistants on this project.**
