# Lux Crypto

Cryptographic primitives for the Lux Network -- post-quantum signatures, key encapsulation, BLS aggregation, threshold signing, ring signatures, and EVM-compatible secp256k1.

```
go get github.com/luxfi/crypto
```

## Architecture

`luxfi/crypto` is the cryptographic foundation for all Lux software. It provides both classical and post-quantum primitives, with automatic CGO acceleration where available (blst for BLS, circl for lattice schemes). The pure-Go fallback path requires no C compiler.

### Post-Quantum (NIST FIPS 203/204/205)

| Package | Algorithm | Standard | Security | Key Sizes |
|---------|-----------|----------|----------|-----------|
| `mldsa/` | ML-DSA | FIPS 204 | 128/192/256-bit (Levels 2/3/5) | 44: 1312/2560 B, 65: 1952/4032 B, 87: 2592/4896 B |
| `mlkem/` | ML-KEM | FIPS 203 | 128/192/256-bit | 512: 800/1632 B, 768: 1184/2400 B, 1024: 1568/3168 B |
| `slhdsa/` | SLH-DSA (FIPS 205, formerly SPHINCS+) | FIPS 205 | 128/192/256-bit (12 variants) | SHA2/SHAKE, fast/small tradeoff |
| `pq/` | Unified PQ interface | -- | Wraps mldsa, mlkem, slhdsa | Mode selection at runtime |

ML-DSA and ML-KEM wrap Cloudflare's circl with ergonomic key serialization. SLH-DSA provides hash-based signatures as a conservative fallback (no lattice assumptions).

### Classical

| Package | Algorithm | Use |
|---------|-----------|-----|
| `bls/` | BLS12-381 (G1 keys, G2 signatures) | Consensus signatures, aggregation, proof-of-possession |
| `secp256k1/` | secp256k1 ECDSA | EVM transaction signing, Ethereum compatibility |
| `secp256r1/` | P-256 ECDSA | TLS, WebAuthn, FIDO2 |
| `ecies/` | ECIES (secp256k1) | Asymmetric encryption for Ethereum-compatible keys |

### Threshold and Multi-Party

| Package | Protocol | Use |
|---------|----------|-----|
| `threshold/` | Threshold signature framework | Interface + registry for pluggable threshold schemes |
| `threshold/bls/` | BLS threshold signatures | t-of-n BLS signing for consensus |
| `cggmp21/` | CGGMP21 (ECDSA threshold) | MPC key generation and signing, Paillier commitments |

### Advanced Constructions

| Package | Construction | Use |
|---------|-------------|-----|
| `ring/` | Ring signatures (LSAG + lattice-based) | Unlinkable signer anonymity |
| `lamport/` | Lamport one-time signatures | Hash-based PQ signatures (stateful) |
| `hpke/` | Hybrid Public Key Encryption | ML-KEM + X25519 hybrid, KEM factory |
| `kem/` | KEM abstraction | ML-KEM, X25519, hybrid combiner |
| `aead/` | AEAD ciphers | AES-256-GCM, ChaCha20-Poly1305 |
| `kdf/` | Key derivation | HKDF, SLIP-10 HD derivation |
| `verkle/` | Verkle tree commitments | State proof compression |
| `kzg4844/` | KZG commitments (EIP-4844) | Blob transaction proofs |
| `ipa/` | Inner product arguments | Verkle proof backend |

### Infrastructure

| Package | Purpose |
|---------|---------|
| `common/` | Address, Hash types (20-byte, 32-byte) |
| `hash/`, `hashing/` | Keccak256, SHA256, RIPEMD160, Blake2b |
| `rlp/` | RLP encoding (Ethereum wire format) |
| `cb58/` | CB58 encoding (Lux address format) |
| `cert/` | TLS certificate management for node identity |
| `signer/` | Transaction signing abstraction |
| `sign/` | Signature scheme registry |
| `secret/` | Secret-safe memory operations (zeroing, constant-time) |
| `address/` | Multi-chain address derivation |
| `gpu/` | GPU-accelerated modular arithmetic bindings |
| `bindings/` | C/Rust FFI exports |

## BLS Signatures

```go
import "github.com/luxfi/crypto/bls"

sk, _ := bls.NewSecretKey()
pk := bls.PublicFromSecretKey(sk)

sig := bls.Sign(sk, []byte("block hash"))
valid := bls.Verify(pk, sig, []byte("block hash"))

// Aggregation
aggSig, _ := bls.AggregateSignatures(sig1, sig2, sig3)
aggPK, _ := bls.AggregatePublicKeys(pk1, pk2, pk3)
valid = bls.Verify(aggPK, aggSig, msg)
```

## Post-Quantum Signatures (ML-DSA)

```go
import "github.com/luxfi/crypto/mldsa"

sk, pk, _ := mldsa.GenerateKey(mldsa.MLDSA87)  // NIST Level 5
sig, _ := sk.Sign(rand.Reader, data, nil)
valid := pk.VerifySignature(data, sig)
```

## Post-Quantum Key Encapsulation (ML-KEM)

```go
import "github.com/luxfi/crypto/mlkem"

sk, pk, _ := mlkem.GenerateKey(mlkem.MLKEM1024)  // NIST Level 5
ciphertext, sharedSecret, _ := pk.Encapsulate()
recovered, _ := sk.Decapsulate(ciphertext)
// sharedSecret == recovered (32 bytes, use as AES key)
```

## Hybrid HPKE

```go
import "github.com/luxfi/crypto/hpke"

// ML-KEM-1024 + X25519 hybrid
suite := hpke.NewHybridSuite()
enc, ct, _ := suite.Seal(recipientPK, plaintext, aad)
pt, _ := suite.Open(recipientSK, enc, ct, aad)
```

## Testing

```bash
go test ./...          # 382 test functions
go test -bench=. ./... # benchmarks
```

Compiled test binaries are provided for quick verification:
- `bls.test` -- BLS signature tests
- `mldsa.test` -- ML-DSA tests
- `mlkem.test` -- ML-KEM tests
- `slhdsa.test` -- SLH-DSA tests
- `crypto.test` -- Core crypto tests

## Papers

- [Lux PQ Crypto Suite](https://github.com/luxfi/papers/blob/main/lux-pq-crypto-suite.pdf) -- parameter selection and security analysis for ML-DSA, ML-KEM, SLH-DSA
- [Lux Hybrid PQ Architecture](https://github.com/luxfi/papers/blob/main/lux-hybrid-pq-architecture.pdf) -- hybrid classical/PQ transition strategy
- [Lux Crypto Agility](https://github.com/luxfi/papers/blob/main/lux-crypto-agility.pdf) -- algorithm negotiation and migration framework
- [Lux Pulsar PQ](https://github.com/luxfi/papers/blob/main/lux-corona-pq.pdf) -- post-quantum ring signatures
- [Lux Universal Threshold Signatures](https://github.com/luxfi/papers/blob/main/lux-universal-threshold-signatures.pdf) -- multi-curve threshold framework

## References

- NIST FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- NIST FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- NIST FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
- [Cloudflare circl](https://github.com/cloudflare/circl) -- underlying lattice implementations
- [BLS12-381](https://hackmd.io/@benjaminion/bls12-381) -- pairing-friendly curve specification

## License

Lux Ecosystem License v1.2. See [LICENSE](LICENSE).
