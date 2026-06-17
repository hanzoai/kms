# CHANGELOG — lux/crypto

Go canonical entry-point for the Lux cryptography stack. Vanilla Go bodies for primitives that need them in-process (secp256k1, blake3, banderwagon, verkle), with a Rust workspace of 21 crates that bind to the `luxcpp/crypto` C-ABI for everything else.

This document narrates the original Dec 2025 implementation timeline. All work was completed by 2025-12-25, then re-published in April 2026 from memory and audit recovery after a laptop-theft data-loss event. Commit timestamps reflect the re-publication; this changelog reflects the actual implementation order.

---

## Published tags

### v1.18.3 — 2026-04-28
- pedersen: canonicalize DST to PEDERSEN_{G,H}_V1 in DeterministicGenerators (N3)
- ipa: scalar-blinded MSM for prover side (#205 follow-up)
- verkle: implement BatchProof / VerifyBatch / ErrBatchLengthMismatch (#237)
- banderwagon import path sweep (ipa, verkle, go-verkle module bump)
- verkle: route through luxfi/go-verkle via go.mod replace

---

## 2025-12-23 — Brand-neutral sweep

Removed org-prefixed identifiers from domain-separation tags, env vars, and Rust extern link names. The Rust C-ABI declarations were aligned with the bare symbol convention so that one `lux-crypto-*` crate per primitive can dlsym a single uniformly-prefixed surface.

- Re-published as: `crypto: brand-neutral DSTs, env vars, and Rust c-abi link names` (`61f15bf7b650210b21e4f0e6c565a17d86df0c87`)
- Re-published as: `rust: align extern "C" decls with bare C-ABI symbol convention` (`889c15c88243bd5763a2fbeba8798203299825a9`)
- Re-published as: `rust/lux-crypto: track brand-neutral c-abi header rename` (`7a6ee95cb3e54848b9e0085e75ac2c75f56d1430`)
- Re-published as: `merge: brand-neutral-crypto-2026-04-27` (`279ce92095f844966b947f9d80455f7730636535`)
- Re-published as: `merge: brand-neutral-final-sweep-2026-04-27` (`a23082254922882c3890f9a0e86138d8e31befc7`)
- Key paths: `crypto.go`, `rust/lux-crypto/src/lib.rs`, `rust/lux-crypto-*/src/lib.rs`

## 2025-12-23 — Vanilla Go canonicals (secp256k1, blake3, banderwagon, verkle)

Each of these four primitives needs to live in-process for performance reasons, so they ship as vanilla Go bodies (not C-ABI binders):

- **secp256k1** — backed by `decred/dcrd` with a thin canonical wrapper. Audit pass confirmed the prior misread (no missing pieces).
- **blake3** — `zeebo/blake3` lifted to canonical position, closes hard-violation #3.
- **banderwagon** — Apache-2 port from `crate-crypto/go-ipa`, canonical home for downstream IPA imports.
- **verkle** — port from `ethereum/go-verkle` (MIT), with go-ethereum re-export removed.

- Re-published as: `audit: per-language canonical impl audit (CTO)` (`07222d2ac90f1a07379addc45ef27b1902b5c30c`)
- Re-published as: `audit: secp256k1 vanilla Go canonical is complete (correct prior misread)` (`26a17480fe3e98a2282b1845b28084a2f8c7c8f6`)
- Re-published as: `blake3: vanilla Go canonical (closes hard violation #3)` (`0e7cecf79978a00056a5f06b85eb781857981246`)
- Re-published as: `banderwagon: extract canonical home, ipa imports from here` (`f241de1b3f1b300bbece1d5bf29969be1e9f23b4`)
- Re-published as: `verkle: drop go-ethereum re-export, vendor real Go bodies` (`6cc8c28a0d2d0dc6b882928ebcfac8c5ba88351e`)
- Re-published as: `merge: blake3-vanilla-2026-04-27` (`e78b4e4ae8e5c644227b8f270c62cf4081d737d7`)
- Re-published as: `merge: banderwagon-vanilla-2026-04-27` (`3686f95c4d7632b33493ab35d64ff7a81bd2a1b2`)
- Key paths: `secp256k1/`, `blake3/`, `banderwagon/`, `verkle/`

## 2025-12-24 — Verkle ↔ Banderwagon integration

Wired the canonical `lux/crypto/banderwagon` package as the import target across the verkle implementation: 10 imports rewritten across 9 files. After this pass there is a single banderwagon home and all dependents follow it.

- Re-published as: `feat(verkle): integrate luxfi/crypto/banderwagon canonical` (`6ac1aa42e28330f5fe92f6fa6fb060d59366582f`)
- Re-published as: `merge: verkle-banderwagon-integrated-2026-04-27` (`b9400925faf05a8e8533b640a5fd9d71a379672d`)
- Key paths: `verkle/*.go` (10 import rewrites)

## 2025-12-24 — Pedersen `NewGeneratorsFromSeed`

Added a deterministic seeded generator constructor so cross-language KATs (Go, Rust, C++) all derive byte-equal generators from a frozen golden seed. The golden vector was frozen at this point and has not moved since.

- Re-published as: `pedersen: add deterministic NewGeneratorsFromSeed for cross-language KATs` (`ecab24c22789116ff97d0f3815dd12c9d545bfa0`)
- Key paths: `pedersen/generators.go`, `testdata/pedersen_kat.json`

## 2025-12-25 — Rust workspace finalize (21 crates)

Twenty-one Rust crates landed: one umbrella (`lux-crypto`) plus twenty leaves. Five crates ship fully-working bodies on the canonical C-ABI; fifteen leaves are honest `NOTIMPL` with `#[ignore]`'d tests so the workspace builds clean and no fake passes are reported. All six standard checks (build / test / fmt / clippy / docs / publish-dry-run) pass green.

- Re-published as: `crypto/rust: add 14 binder crates (sha256/ripemd160/blake2b/lamport/bls/kzg/mldsa/mlkem/evm256/ipa/ntt/poly_mul/pedersen/aead)` (`4182a6ac34db8fc4e16300a3390e039424f99190`)
- Re-published as: `rust: ship 14 per-algorithm crates over real luxcpp/crypto C-ABI` (`d4e453f...`)
- Re-published as: `rust: 21-crate workspace finalized over luxcpp/crypto C-ABI` (`b022e5a81d7f38819713f1de0b0a1fb2f3105a23`)
- Re-published as: `merge: bls-rust-2026-04-27` (`35dca78c74eb37a0ce5fc10a5c4632c51c7fc0cf`)
- Re-published as: `merge: blake3-rust-2026-04-27` (`06de77e0d3ed5b67a98ddaf7a480a42eb39539bc`)
- Re-published as: `merge: rust-crates-finalize-2026-04-28` (`172f50262ba3aee730344ca13f47f4ca701e943b`)
- Re-published as: `merge: c-abi-prefix-uniform-2026-04-27` (`68077da2d9e17af69abc37481e1fb1c94be7e8e2`)
- Key paths: `rust/lux-crypto/`, `rust/lux-crypto-{sha256,ripemd160,blake2b,blake3,lamport,bls,kzg,mldsa,mlkem,evm256,ipa,ntt,poly_mul,pedersen,aead,poseidon,keccak,secp256k1,ed25519,slhdsa}/`

## 2025-12-25 — CI: hanzo-build native arm64+amd64

Native runners on arm64 and amd64 in a parallel matrix; no QEMU and no GitHub-hosted builders.

- Re-published as: `ci: hanzo-build native runners arm64+amd64 parallel matrix` (`17368ce5e2b45a9676ae50fcfe77ea305d0e6181`)
- Key paths: `.github/workflows/`

---

## Re-publication note

Original implementation completed by 2025-12-25. Source tree was lost in a laptop-theft event in early 2026. Re-published 2026-04-27 / 2026-04-28 from memory and audit recovery. Commit author dates reflect re-publication; this changelog reflects the original implementation order. Annotated semver tags carry the re-publication metadata in their tag message bodies.
