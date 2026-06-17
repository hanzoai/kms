# luxfi/crypto AUDIT

Date: 2026-04-26
Scope: existing algorithm packages and what each backend (vanilla, cgo, gpu) currently has.

`luxfi/crypto` is the canonical Go entry point. Every consumer
(`lux/node`, `zoo/node`, `hanzo/node-go`, `hanzod`, `parsd`, `zood`,
`lux/precompile`, `lux/cli`, …) imports from here. Behind every public
function there are up to three implementations dispatched by build tags
plus a runtime backend selector (`backend.Default()`).

| Tag-set        | Path     | Notes                                     |
|----------------|----------|-------------------------------------------|
| `!cgo`         | vanilla  | Pure Go reference. Always available.      |
| `cgo`          | cgo      | Native binding (blst, libsecp256k1, ckzg) |
| `cgo,accel`    | gpu      | Routes batch ops through `lux/accel`      |

`backend.Default()` reads `CRYPTO_BACKEND` (`auto|vanilla|cgo|gpu`)
and falls back to `auto`. `auto` picks the highest-priority backend the
binary was compiled with. The deprecated `LUX_CRYPTO_BACKEND` is read for
one release with a deprecation warning; remove in v2.

## Per-algorithm state

Legend: V = vanilla Go, C = cgo, G = GPU via lux/accel, T = tests.

| Algorithm | V | C | G | T | Notes |
|-----------|---|---|---|---|-------|
| address      | Y | - | - | - | Bech32/cb58 helpers, no compute kernel |
| aead         | Y | - | - | - | XChaCha20-Poly1305 wrapper around stdlib |
| aggregated   | Y | - | - | Y | Signature aggregator manager (BLS) |
| bigmodexp    | Y | - | - | - | EVM precompile reference impl |
| bindings/cabi| - | E | - | - | `c-shared` exporter; produces libluxcrypto.{dylib,so} |
| bitutil      | Y | - | - | - | EVM bit utilities (no kernel) |
| blake2b      | Y | A | G* | Y | AVX2 asm in `_amd64.s`. GPU added (batch). |
| bls          | Y | Y | G* | Y | circl pure-Go (`!cgo`) + blst (`cgo`). GPU added (batch verify/aggregate). |
| bls12381     | Y | Y | - | - | gnark (`!cgo`) + blst (`cgo`) field arithmetic |
| bn256        | Y | Y | - | Y | cloudflare + gnark + google fallbacks |
| cb58         | Y | - | - | Y | Pure Go base58 + checksum |
| cert         | - | - | - | - | Empty placeholder (TLS cert helpers) |
| cggmp21      | Y | - | - | - | Threshold ECDSA, Paillier — pure Go |
| cgo          | - | E | - | - | luxlink: pkg-config aggregator, no algorithms |
| common       | Y | - | - | - | Hash, hex, types — utility |
| da           | - | - | - | - | Empty placeholder |
| dist         | - | E | - | - | Built C-shared artefact (libluxcrypto.dylib + .h) |
| docs         | - | - | - | - | fumadocs site |
| ecies        | Y | - | - | Y | Hybrid encryption — pure Go |
| encryption   | Y | - | - | Y | age + HPKE wrappers |
| gpu          | - | - | E | - | Existing thin GPU stub. Replaced by per-alg gpu paths. |
| hash         | Y | - | G* | Y | SHA, BLAKE, Keccak, Poseidon2 helpers. GPU added (batch). |
| hashing      | Y | - | - | - | Re-export under hashing/hashing |
| hpke         | Y | - | - | - | Stdlib `crypto/hpke` wrapper (Go 1.26) |
| ipa          | Y | - | - | Y | gnark IPA + bandersnatch + banderwagon |
| kdf          | Y | - | - | - | Stdlib HKDF wrapper |
| kem          | Y | Y | - | - | circl ML-KEM + hybrid X-Wing |
| kzg4844      | Y | Y | G* | Y | gokzg (`!ckzg`) + ckzg (`cgo,ckzg`). GPU added (batch verify). |
| lamport      | Y | - | - | Y | Hash-based OTS — pure Go |
| mldsa        | Y | - | G* | Y | circl FIPS-204. GPU added (batch sign/verify) when accel exposes ML-DSA. |
| mlkem        | Y | * | G* | Y | circl FIPS-203. cgo file is currently a placeholder (mlkem_c.go). GPU added (batch encaps/decaps). |
| pq           | Y | - | - | - | Re-export aggregator over mldsa+mlkem+slhdsa |
| precompile   | Y | - | - | Y | EVM precompile impls — pure Go |
| ring         | Y | - | - | Y | LSAG + Lattice ring sigs — pure Go |
| rlp          | Y | - | - | - | Pure Go RLP |
| secp256k1    | Y | Y | G* | Y | dcrd (`!cgo`) + libsecp256k1 (`cgo`). GPU added (batch ECDSA verify). |
| secp256r1    | Y | - | - | - | NIST P-256 verifier (RIP-7212) |
| secret       | Y | - | - | Y | Go 1.26 runtime/secret wrapper |
| sign         | - | - | - | - | Empty placeholder |
| signer       | Y | - | - | Y | Hybrid BLS+Pulsar signer |
| signify      | Y | - | - | Y | OpenBSD-style signify |
| slhdsa       | Y | - | - | Y | circl FIPS-205 — pure Go |
| threshold    | Y | - | - | Y | Threshold scheme registry + BLS impl |
| verkle       | Y | - | - | - | go-verkle wrapper |

Legend:
- `Y` = real implementation present
- `*` = placeholder file exists, real implementation pending or routed elsewhere
- `E` = exporter/aggregator (not an algorithm)
- `G*` = GPU dispatcher added by this commit; falls back to vanilla/cgo when accel
   is not available (`!cgo` build, no GPU device, or operation not supported)
- `-` = not applicable / not present

## Canonical naming

Two synonyms exist in the tree because both names appear in upstream specs.
We expose **both** import paths to avoid breaking consumers; the
`<canonical>/<synonym>.go` file is a 4-line re-export that imports the
canonical package. The canonical name is the explicit FIPS / RFC name:

| Canonical | Synonym (kept for compat) |
|-----------|---------------------------|
| `bls12381` | `bls` (signature scheme; uses bls12381 field) |
| `bn254`    | `bn256` (curve order, equivalent name) |
| `kzg4844`  | (no synonym) |

For the new Phase-1 luxcpp/crypto algorithm list we add new dirs only when the
algorithm did not already exist:

- Added in this commit: `keccak/`, `sha256/`, `sha3/`, `ripemd160/`,
  `ed25519/`, `pedersen/`, `poseidon/`, `ntt/`, `polymul/` (= luxcpp's
  poly_mul), `evm256/`, `bn254/` (canonical alias for `bn256`),
  `modexp/` (canonical alias for `bigmodexp`).
- Already present: `aead`, `blake2b`, `bls`, `bls12381`, `bn256`,
  `cggmp21`, `ipa`, `kzg4844`, `lamport`, `mldsa`, `mlkem`, `bigmodexp`,
  `secp256k1`, `secp256r1`, `slhdsa`, `verkle`, `threshold/bls`.
- Deliberately NOT created here:
  * `sr25519/` — Substrate-specific schnorrkel; no in-tree consumer
    requires it today and adding a dependency just for a thin wrapper
    fails the philosophy. Will be added with first real consumer.
  * `frost/` — FROST is already exposed via
    `github.com/luxfi/crypto/threshold` (SchemeFROST) with the adapter
    living in `github.com/luxfi/mpc/pkg/threshold`. A separate `frost/`
    dir would duplicate that surface.
  * `corona/` — implemented natively in `github.com/luxfi/corona/threshold`
    which registers itself with `crypto/threshold`. Same reason as frost.

## Backend selection

```go
import "github.com/luxfi/crypto/backend"

backend.Default()       // returns Vanilla|CGo|GPU based on build tags + env
backend.SetDefault(b)   // override programmatically
backend.Available(b)    // probe whether b is usable
```

Environment override: `CRYPTO_BACKEND=vanilla|cgo|gpu|auto`. Deprecated
alias `LUX_CRYPTO_BACKEND` is honored for one release.

## Honest gaps (Phase 3 / 4)

1. **luxcpp/crypto C-ABI binding (Phase 1 sibling)**: spec mentioned
   `luxcpp/crypto/c-abi/lux_crypto.h` — that header does not yet exist
   in the luxcpp tree (only `c-abi/hash_types.h` from upstream ethash is
   present). When the sibling agent lands the unified C-ABI, the
   `cgo.go` files in each algorithm package will be rewritten to use it
   directly. Today the cgo paths use the per-library bindings already in
   place (`blst`, `libsecp256k1`, `ckzg`).

2. **GPU coverage**: `lux/accel` exposes batch kernels for
   SHA256, Keccak256, Poseidon, ECDSA, Ed25519, BLS verify+aggregate,
   Merkle, plus ML-KEM and ML-DSA. Algorithms without a kernel
   (slhdsa, verkle, kzg4844 single-blob path) keep vanilla/cgo only —
   gpu.go in those packages reports `accel.ErrNotSupported` and the
   public API transparently falls back to the next backend.

3. **mlkem cgo file**: `mlkem/mlkem_c.go` was a placeholder for future
   AVX2/AVX512 assembly. Today the `cgo` build is identical to `!cgo`
   (both circl). Documented; intentional.

4. **`gpu/`** top-level package previously held a single stub that returned
   "GPU not available" everywhere. We keep the file (consumers import it)
   but mark it Deprecated; new code should call the algorithm packages
   directly which dispatch to GPU internally.

5. **`cert/`, `da/`, `sign/`** dirs are empty placeholders from earlier
   reorganizations. Left in place to avoid breaking tags/branches; will
   be deleted in a follow-up commit.
