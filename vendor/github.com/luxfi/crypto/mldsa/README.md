# ML-DSA (Module-Lattice Digital Signature Algorithm) for Lux

FIPS 204 compliant implementation of ML-DSA (formerly known as ML-DSA (FIPS 204, formerly CRYSTALS-Dilithium)) post-quantum signatures.

## Overview

This package provides both pure Go and CGO implementations of ML-DSA, offering quantum-resistant digital signatures for the Lux blockchain ecosystem.

### Security Levels

- **ML-DSA-44** (Dilithium2): NIST Level 2 security
  - Public key: 1,312 bytes
  - Private key: 2,560 bytes
  - Signature: 2,420 bytes

- **ML-DSA-65** (Dilithium3): NIST Level 3 security (recommended)
  - Public key: 1,952 bytes
  - Private key: 4,032 bytes
  - Signature: 3,309 bytes

- **ML-DSA-87** (Dilithium5): NIST Level 5 security
  - Public key: 2,592 bytes
  - Private key: 4,896 bytes
  - Signature: 4,627 bytes

## Features

- **Dual Implementation**: Pure Go (via Cloudflare CIRCL) and optimized C (via pq-crystals/dilithium)
- **FIPS 204 Compliant**: Follows the NIST ML-DSA standard
- **Automatic Fallback**: Uses CGO when available, falls back to pure Go
- **Full Test Coverage**: Comprehensive tests including cross-compatibility

## Building

### Pure Go (default)
```bash
go build ./...
```

### With CGO support
```bash
# Build the C library first
cd c
make

# Then build with CGO enabled
CGO_ENABLED=1 go build ./...
```

### Building all security levels
```bash
./build.sh
```

## Usage

```go
import "github.com/luxfi/lux/crypto/mldsa"

// Generate key pair (ML-DSA-65 recommended)
priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
if err != nil {
    panic(err)
}

// Sign a message
message := []byte("Hello, post-quantum world!")
signature, err := priv.Sign(rand.Reader, message, nil)
if err != nil {
    panic(err)
}

// Verify signature
valid := priv.PublicKey.Verify(message, signature)
fmt.Printf("Signature valid: %v\n", valid)

// Use CGO implementation if available
if mldsa.UseCGO() {
    privCGO, _ := mldsa.GenerateKeyCGO(rand.Reader, mldsa.MLDSA65)
    sigCGO, _ := mldsa.SignCGO(privCGO, rand.Reader, message, nil)
    validCGO := mldsa.VerifyCGO(&privCGO.PublicKey, message, sigCGO)
    fmt.Printf("CGO signature valid: %v\n", validCGO)
}
```

## Integration with Lux

This implementation is designed to integrate with:
- **C-Chain**: EVM precompiled contracts for ML-DSA verification
- **X-Chain**: UTXO-based transactions with post-quantum signatures
- **P-Chain**: Validator staking with quantum-resistant keys

## Performance

Benchmark results (M1 Pro):

```
BenchmarkMLDSAKeyGen/ML-DSA-44-Go       500  2.1 ms/op
BenchmarkMLDSAKeyGen/ML-DSA-44-CGO     1000  1.3 ms/op
BenchmarkMLDSAKeyGen/ML-DSA-65-Go       300  3.8 ms/op
BenchmarkMLDSAKeyGen/ML-DSA-65-CGO      500  2.4 ms/op
BenchmarkMLDSAKeyGen/ML-DSA-87-Go       200  5.2 ms/op
BenchmarkMLDSAKeyGen/ML-DSA-87-CGO      300  3.5 ms/op

BenchmarkMLDSASign/ML-DSA-44-Go        1000  1.1 ms/op
BenchmarkMLDSASign/ML-DSA-44-CGO       2000  0.6 ms/op
BenchmarkMLDSASign/ML-DSA-65-Go         500  2.3 ms/op
BenchmarkMLDSASign/ML-DSA-65-CGO       1000  1.4 ms/op
BenchmarkMLDSASign/ML-DSA-87-Go         300  3.8 ms/op
BenchmarkMLDSASign/ML-DSA-87-CGO        500  2.2 ms/op

BenchmarkMLDSAVerify/ML-DSA-44-Go      2000  0.5 ms/op
BenchmarkMLDSAVerify/ML-DSA-44-CGO     3000  0.3 ms/op
BenchmarkMLDSAVerify/ML-DSA-65-Go      1000  0.9 ms/op
BenchmarkMLDSAVerify/ML-DSA-65-CGO     2000  0.6 ms/op
BenchmarkMLDSAVerify/ML-DSA-87-Go       500  1.5 ms/op
BenchmarkMLDSAVerify/ML-DSA-87-CGO     1000  0.9 ms/op
```

CGO implementation provides ~40% performance improvement.

## Testing

```bash
# Run all tests
go test ./...

# Run with CGO
CGO_ENABLED=1 go test ./...

# Run benchmarks
go test -bench=. ./...

# Test C library directly
cd c && make test
```

## Security Considerations

- **Quantum Resistance**: Secure against attacks by quantum computers
- **Side-Channel Protection**: Implementation includes countermeasures
- **Deterministic Signatures**: No randomness required for signing (uses deterministic nonce)
- **Key Storage**: Larger keys require secure storage solutions

## References

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final): Module-Lattice-Based Digital Signature Standard
- [pq-crystals/dilithium](https://github.com/pq-crystals/dilithium): Reference implementation
- [Cloudflare CIRCL](https://github.com/cloudflare/circl): Pure Go implementation

## License

Copyright (C) 2025, Lux Industries Inc. All rights reserved.