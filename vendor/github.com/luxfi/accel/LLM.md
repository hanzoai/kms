# Lux Accel - GPU Acceleration for Chain Operations

High-level GPU acceleration package for blockchain and cryptographic operations.

## Architecture

```
lux/accel/
├── accel.go           # Public API
├── defaults.go        # (!cgo) No-GPU defaults
├── accel_c.go         # (cgo) CGO implementations
├── session.go         # (!cgo) Session impl
├── session_c.go       # (cgo) Session CGO
├── session_types.go   # Session types/interface
├── tensor.go          # (!cgo) Tensor impl
├── tensor_c.go        # (cgo) Tensor CGO
├── tensor_types.go    # Tensor types/interface
├── ops.go             # (!cgo) Ops interfaces
├── ops_c.go           # (cgo) Ops CGO
├── backend.go         # Backend types
├── capabilities.go    # (!cgo) Capabilities impl
├── capabilities_c.go  # (cgo) Capabilities CGO
└── ops/               # Specialized operations
    ├── crypto/        # Cryptographic operations
    ├── zk/            # Zero-knowledge proofs
    ├── fhe/           # Fully homomorphic encryption
    ├── lattice/       # Lattice-based crypto
    ├── dex/           # DEX operations
    └── consensus/     # Consensus acceleration
```

## Build Tags

| Suffix | Build Tag | Purpose |
|--------|-----------|---------|
| `foo.go` | `!cgo` | Pure Go implementation |
| `foo_c.go` | `cgo` | CGO/GPU acceleration |
| `foo_types.go` | (none) | Shared types, interfaces |
| `foo_default.go` | `!accel` | Falls back to CPU |
| `foo_gpu.go` | `accel` | GPU implementation |
| `foo_cpu.go` | (none) | CPU implementation |

## Backends

| Backend | Platform | Priority |
|---------|----------|----------|
| CUDA | Linux/Windows | 1 (highest) |
| Metal | macOS/iOS | 2 |
| WebGPU | All (Dawn) | 3 |
| CPU | All | 4 (fallback) |

## Operations

### Crypto (`ops/crypto`)
- Batch signature verification (ECDSA, Ed25519, BLS)
- Batch hashing (SHA256, Keccak256, Poseidon)
- MSM (Multi-Scalar Multiplication)
- BLS aggregation

### ZK (`ops/zk`)
- NTT/iNTT transforms
- Polynomial operations
- FFT/iFFT
- Field arithmetic (BN254)

### FHE (`ops/fhe`)
- BFV encryption/decryption
- CKKS encryption/decryption
- Homomorphic operations
- Bootstrapping
- Multi-GPU coordination

### Lattice (`ops/lattice`)
- Kyber key generation
- Kyber encapsulation/decapsulation
- Dilithium signing/verification
- Polynomial NTT/iNTT

### DEX (`ops/dex`)
- Constant product swaps
- Order matching
- TWAP computation
- Concentrated liquidity

### Consensus (`ops/consensus`)
- Batch signature verification
- Merkle tree construction
- Block validation acceleration

## Usage

```go
package main

import "github.com/luxfi/accel"

func main() {
    // Initialize
    if err := accel.Init(); err != nil {
        panic(err)
    }
    defer accel.Shutdown()

    // Check availability
    if !accel.Available() {
        println("No GPU available, using CPU")
    }

    // Batch BLS verification (GPU-accelerated)
    results, err := accel.BLSBatchVerify(pubkeys, sigs, msgs)
    if err == accel.ErrNotSupported {
        // Fall back to sequential verification
    }

    // Create session for advanced ops
    sess, err := accel.NewSession()
    if err != nil {
        panic(err)
    }
    defer sess.Close()

    // Use specialized operations
    zk := sess.ZK()
    err = zk.NTT(input, output, roots, modulus)
}
```

## Building

### Without CGO (no GPU)
```bash
CGO_ENABLED=0 go build ./...
# CPU fallbacks available for all operations
```

### With CGO (GPU support)
```bash
CGO_ENABLED=1 go build ./...
# Requires luxcpp/gpu built and installed
```

### With accel tag (full GPU ops)
```bash
go build -tags=accel ./...
# Enables GPU implementations in ops/*
```

## Related

- `lux/gpu` - Low-level GPU array operations
- `luxcpp/gpu` - C++ backend library
