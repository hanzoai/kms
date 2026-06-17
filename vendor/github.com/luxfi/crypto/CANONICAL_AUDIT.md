# Canonical Per-Language Implementation Audit

Date: 2026-04-27
Scope: read-only audit of `~/work/lux/crypto/*` and `~/work/luxcpp/crypto/*`.

## Directive

> no wrapper no compat shim; one and one way only per C++/Go/CPU/GPU etc rust can
> bind shit but always have 100% real optimized CPU versions + GPU in C++ + vanilla
> Go (which can also CgO the CPU or GPU C++)

Per-language canonical pattern:

- C++/CPU canonical: `luxcpp/crypto/<alg>/cpp/<alg>.{cpp,hpp}`
- C++/GPU canonical: `luxcpp/crypto/<alg>/gpu/{metal,cuda,wgsl}/`
- Go canonical: `lux/crypto/<alg>/<alg>.go` — VANILLA Go real impl (stdlib / `golang.org/x/crypto` / `consensys/gnark-crypto` / `cloudflare/circl` / `zeebo/blake3` / etc. count as compliant)
- Rust: `lux/crypto/rust/lux-crypto-<alg>/` binds to C++ via `extern "C"` + `build.rs`

Go cgo path is acceptable as an OPT-IN accelerator only when there is also a real vanilla Go canonical body for the same package.

## Audit Table

Legend: OK = compliant; MISSING = not present; STDLIB = stdlib/established Go crate (counts as vanilla); CGO-ONLY = violation (only path is cgo wrapper); N/A = not applicable.

| Algo            | C++/CPU              | C++/GPU                   | Go vanilla canonical                            | Go cgo accelerator        | Rust binding                          |
|-----------------|----------------------|---------------------------|-------------------------------------------------|---------------------------|---------------------------------------|
| keccak          | OK (cpp/keccak.cpp)  | OK (metal/cuda/wgsl)      | OK (`golang.org/x/crypto/sha3`)                 | none (single path)        | OK (`lux-crypto-keccak`)              |
| sha256          | OK (cpp/sha256.cpp)  | OK (metal)                | OK (`crypto/sha256` stdlib)                     | optional GPU batch only   | MISSING                               |
| ripemd160       | OK (cpp/ripemd.cpp)  | OK (metal)                | OK (`golang.org/x/crypto/ripemd160`)            | none                      | MISSING                               |
| blake2b         | OK (cpp/blake2b.cpp) | OK (metal)                | OK (real vanilla + AVX2/AVX asm)                | none                      | MISSING                               |
| blake3          | OK (cpp/blake3.cpp)  | OK (metal/cuda/wgsl)      | MISSING (`lux/crypto/blake3` directory absent)  | n/a                       | OK (`lux-crypto-blake3`)              |
| poseidon        | MISSING              | OK (metal)                | OK (`gnark-crypto/.../poseidon2`)               | none                      | MISSING                               |
| secp256k1       | OK (cpp/curve.hpp+)  | OK (metal/cuda/wgsl)      | OK (`!cgo` -> `decred/dcrd/dcrec/secp256k1/v4`) | optional cgo libsecp256k1 accelerator | OK (`lux-crypto-secp256k1`) |
| ed25519         | OK (cpp/ed25519.cpp) | OK (metal/cuda/wgsl)      | OK (`crypto/ed25519` stdlib)                    | optional GPU batch only   | OK (`lux-crypto-ed25519`)             |
| bls (BLS12-381 sig API) | OK (cpp/bls_*.cpp) | OK (metal/cuda/wgsl) | OK (`!cgo` -> `cloudflare/circl/sign/bls`; `cgo` -> blst) | blst optional via `cgo` build tag | MISSING |
| bls12381 (low-level) | OK (cpp/bls)    | OK                        | OK (`!cgo` gnark-crypto; `cgo` blst)             | blst optional             | (covered by `lux-crypto-bls` placeholder; no crate yet) |
| AEAD chacha20-poly1305 | MISSING       | MISSING                   | OK (`golang.org/x/crypto/chacha20poly1305` + `crypto/aes`) | none           | MISSING                               |
| lamport         | OK (cpp/lamport.cpp) | OK (metal)                | OK (real vanilla, `crypto/sha256`+`sha512`)     | none                      | MISSING                               |
| banderwagon     | MISSING              | MISSING                   | MISSING (dir empty)                             | n/a                       | MISSING                               |
| pedersen        | MISSING              | MISSING                   | OK (real vanilla, `gnark-crypto/bn254`)         | none                      | MISSING                               |
| IPA             | MISSING              | OK (metal)                | OK (vendored go-ipa style impl in `ipa/`)       | none                      | MISSING                               |
| verkle          | MISSING              | MISSING                   | VIOLATION (re-export of `ethereum/go-verkle`)   | n/a                       | MISSING                               |
| evm256 (bn254 precompiles) | MISSING   | OK (metal/cuda/wgsl)      | OK (real vanilla, `gnark-crypto/bn254`)         | none                      | MISSING                               |
| kzg (kzg4844)   | OK (cpp/kzg.cpp)     | OK (metal)                | OK (`!cgo` gokzg; `cgo` ckzg)                   | ckzg optional             | MISSING                               |
| mldsa           | OK (cpp/mldsa.cpp + pqclean) | OK (metal/cuda/wgsl) | OK (`circl/sign/mldsa/mldsa{44,65,87}`)        | optional ckzg-style C path (build.sh) | MISSING                |
| mlkem           | OK (cpp/mlkem.cpp + pqclean) | OK (metal/cuda/wgsl) | OK (`circl/kem/mlkem/mlkem{512,768,1024}`)     | placeholder (`mlkem_c.go` is stub) | MISSING                       |
| slhdsa          | OK (cpp/slhdsa.cpp + pqclean) | OK (metal/cuda/wgsl) | OK (`circl/sign/slhdsa`)                       | optional via build.sh     | OK (`lux-crypto-slhdsa`)              |
| NTT             | PARTIAL (header only, `cpp/ntt.hpp`) | OK (metal/cuda/wgsl) | OK (real vanilla Cooley-Tukey)             | none                      | MISSING                               |
| poly_mul        | PARTIAL (header only, `cpp/poly_mul.hpp`) | OK (metal/cuda/wgsl) | OK (real vanilla schoolbook negacyclic)  | none                      | MISSING                               |

## Violation Count

Hard violations (vanilla Go canonical missing or itself a re-export/wrapper):

1. **blake3** — `lux/crypto/blake3/` directory does not exist. C++ + Rust crate exist, but no Go canonical at all.
2. **verkle** — `lux/crypto/verkle/verkle.go` is a pure re-export of `github.com/ethereum/go-verkle` (`type X = upstream.X`, `var Fn = upstream.Fn`). Violates "luxfi only" + "no wrapper" rules.
3. **banderwagon** — `lux/crypto/banderwagon/` directory empty. No Go canonical, no C++, no Rust.

(Earlier draft listed `secp256k1` as a hard violation; that was a misread. `secp256k1.go` is a complete `!cgo` vanilla Go canonical via `decred/dcrd/dcrec/secp256k1/v4` (Sign/Verify/RecoverPubkey/CompressPubkey/DecompressPubkey). Cgo libsecp256k1 is the opt-in accelerator. Cross-backend KAT 2026-04-27 confirms byte-for-byte parity.)

Soft violations (luxcpp C++/CPU body missing for an algo that has a Go canonical):

5. **poseidon/cpp** — only `gpu/metal/poseidon.metal` exists; no `cpp/poseidon.cpp`. Go canonical compliant via gnark-crypto. Audit gap is on the C++ side.
6. **aead/cpp** — fully empty in luxcpp. Go vanilla via stdlib + `x/crypto/chacha20poly1305` is fine; if accelerated C++/GPU is desired this needs authoring.
7. **pedersen/cpp** — empty in luxcpp. Go vanilla (gnark) is fine.
8. **ipa/cpp** — empty in luxcpp (gpu metal exists). Go vanilla is fine (vendored go-ipa).
9. **evm256/cpp** — empty in luxcpp (gpu present). Go vanilla (gnark) is fine.
10. **ntt/cpp**, **poly_mul/cpp** — only `.hpp` header, no `.cpp` body. Go vanilla is fine.

Rust gaps (algos with C++/CPU + Go vanilla but no Rust crate yet):

`sha256`, `ripemd160`, `blake2b`, `lamport`, `mldsa`, `mlkem`, `bls`, `kzg`, `evm256`, `ipa`, `ntt`, `poly_mul`, `pedersen`, `aead`. These are not violations of the "vanilla Go must be real" rule; they are coverage gaps for the Rust binder lane.

## Total

- Hard violations: **3** (blake3 missing, verkle wrapper, banderwagon empty)
- Soft violations (C++/CPU body missing): **6**
- Rust binder gaps: **14**

## Remediation Priority

P0 — Hard violations (block "one way" claim):

1. **verkle** — author real luxfi vanilla Go canonical. Source to port: `github.com/ethereum/go-verkle` MIT, port the trie + proof logic into `lux/crypto/verkle/verkle.go` under luxfi copyright. Drop the `upstream` re-export.
2. **blake3** — create `lux/crypto/blake3/blake3.go` using `github.com/zeebo/blake3` (BSD-3, pure Go, AVX2/NEON). Mirror the keccak/sha256 batch-with-GPU-fallback pattern.
3. **banderwagon** — create `lux/crypto/banderwagon/banderwagon.go`. Source: `github.com/crate-crypto/go-ipa/banderwagon` (Apache-2/MIT) — port directly, luxfi copyright.

P1 — luxcpp C++/CPU bodies for algos that already have Go canonical (so the canonical pattern is symmetric across languages):

5. `luxcpp/crypto/poseidon/cpp/poseidon.{cpp,hpp}` — poseidon2 over BN254 Fr. Reference: gnark-crypto Go impl, transliterate.
6. `luxcpp/crypto/ntt/cpp/ntt.cpp` — body to match existing `ntt.hpp`.
7. `luxcpp/crypto/poly_mul/cpp/poly_mul.cpp` — body to match existing `poly_mul.hpp`.
8. `luxcpp/crypto/evm256/cpp/evm256.{cpp,hpp}` — bn254 precompiles (Add/Mul/Pairing) in C++. Reference: blst or arkworks-rs.
9. `luxcpp/crypto/ipa/cpp/ipa.{cpp,hpp}` — Bulletproofs-style IPA over Banderwagon. Reference: crate-crypto/go-ipa.
10. `luxcpp/crypto/pedersen/cpp/pedersen.{cpp,hpp}` — Pedersen vector commitments over BN254 G1.
11. `luxcpp/crypto/aead/cpp/aead.{cpp,hpp}` — ChaCha20-Poly1305 + AES-256-GCM. Reference: BoringSSL, libsodium.

P2 — Rust binder coverage (one crate per algo with luxcpp `lib<alg>_cpu.a`):

12. Create `lux/crypto/rust/lux-crypto-{sha256,ripemd160,blake2b,lamport,bls,kzg,mldsa,mlkem,evm256,ipa,ntt,poly_mul,pedersen,aead}/` with `build.rs` matching the keccak/secp256k1/ed25519/blake3/slhdsa pattern.

## Files Requiring Vanilla Go Authoring (Hard Violations)

| File to author                                          | Source to port from                                                        |
|---------------------------------------------------------|-----------------------------------------------------------------------------|
| `/Users/z/work/lux/crypto/verkle/verkle.go`             | `github.com/ethereum/go-verkle` (MIT) — full reimpl, luxfi copyright        |
| `/Users/z/work/lux/crypto/blake3/blake3.go`             | wrap `github.com/zeebo/blake3` (BSD-3) — counts as vanilla per directive    |
| `/Users/z/work/lux/crypto/banderwagon/banderwagon.go`   | `github.com/crate-crypto/go-ipa/banderwagon` (Apache-2/MIT)                 |

## Notes

- `bls` and `bls12381` already follow the correct dual-build pattern: `!cgo` -> circl/gnark-crypto vanilla, `cgo` -> blst. This is the reference pattern other algos should follow.
- `mldsa`, `mlkem`, `slhdsa` are circl-backed — circl is a real Go crypto crate, counts as vanilla per directive.
- `poseidon` has a C++ GPU kernel but no C++/CPU body. Go canonical works via gnark-crypto. Symmetry gap is luxcpp side only.
- `kzg4844` package follows correct pattern (`!cgo` gokzg vanilla, `cgo` ckzg accelerator). Compliant.
