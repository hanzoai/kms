# Lux Math — High-Performance Cryptographic Substrate

LP-107 reference implementation. The `luxfi/math` Go module owns the
canonical Go reference for every cryptographic-math primitive that
Lux protocols share, with a backend interface that lets native CPU
(AVX2 / NEON / cgo+C++) and GPU (CUDA / Metal / WGSL) realizations
drop in behind it.

## Substrate packages (LP-107 Phase 2)

| Package | Owns | Status |
|---|---|---|
| [`params`](./params/) | ModulusID, NTTParamID, FHEParamID, PulsarParamID, HashSuiteID, BackendID; KAT header schema | ✅ pure-Go reference, validated |
| [`backend`](./backend/) | Policy enum (PureGo / NativeCPU / GPUPreferred / GPURequired), Resolve() dispatch | ✅ pure-Go reference, validated |
| [`codec`](./codec/) | Bounded readers (closes lattice issues #2 + #4 DoS class) | ✅ pure-Go reference, validated |
| [`modarith`](./modarith/) | Barrett, Montgomery, AddMod / SubMod / MulMod, ReductionMode | ✅ pure-Go reference, validated |
| [`ntt`](./ntt/) | NTT Service + Backend interface; pure-Go backend delegates to `lattice/v7/ring.SubRing.NTT/INTT` | ✅ pure-Go reference, validated |
| [`poly`](./poly/) | Polynomial Add / Sub / ScalarMul / PointwiseMul / negacyclic Mul (via NTT round-trip) | ✅ pure-Go reference, validated |
| [`rns`](./rns/) | RNS Basis primitives (single + multi-prime towers) | ✅ pure-Go reference, validated |
| [`sample`](./sample/) | Uniform / Ternary / CenteredBinomial / DiscreteGaussianRejection samplers | ✅ pure-Go reference, validated |

## Architecture invariants

* **Go is the canonical semantic reference.** C++ / GPU backends
  realize the same contract; KATs prove byte-equality.
* **Backend selection MUST NOT alter transcript bytes** for consensus
  paths. Default policy is `PolicyPureGo` or `PolicyNativeCPU`.
* **No unbounded codec readers.** Every wire-format decode goes
  through `codec.Reader`; the `ReadUint64Slice` recursion + OOM bug
  classes are fixed centrally.
* **No re-implementation.** Where the canonical impl already lives
  in `luxfi/lattice` (Lattigo-derived NTT/Montgomery), the substrate
  delegates rather than fork. LP-107 Phase 3 inverts the dependency.
* **One ID space.** `params.ModulusID` / `NTTParamID` / etc. are
  stable strings; renaming is a breaking change. KATs key off them.

## Test posture

```bash
GOWORK=off go test ./...
```

| Package | Tests |
|---|---|
| `params` | ModulusID/NTTParamID/FHEParamID/PulsarParamID/HashSuiteID/BackendID validation; KATHeader required-fields |
| `backend` | Policy String + Validate; Resolve fallback chain (PureGo / NativeCPU / GPUPreferred / GPURequired); GPU-required-no-GPU returns ErrUnavailable |
| `codec` | Limits validation; Uvarint round-trip; happy-path uint16/32/64 slice reads; **regression test for lattice issue #4 (70T-element attack input rejected with LimitError)**; depth + frame-bytes caps |
| `modarith` | NewModulus rejects zero/even; QInv satisfies q\*QInv ≡ -1 mod 2^64; AddMod / SubMod / MulMod cross-checked vs math/big across 1000 random pairs; Montgomery round-trip + 100 randomized MontMul-vs-MulMod cross-checks; LazyModeFits |
| `ntt` | Params validation; PureGo round-trip on Pulsar N=256; batch round-trip; **determinism across two Service instances** |
| `poly` | Add+Sub round-trip; ScalarMul; **negacyclic Mul** via NTT (a=2 \* b=3 → coefficient 0 = 6, others = 0) |
| `rns` | Basis construction (single-prime + two-prime); rejection of empty + even moduli |
| `sample` | Uniform determinism (same seed → byte-equal output); Ternary distribution + balance; CenteredBinomial range-bounded; DiscreteGaussianRejection 1000-sample range |

## Migration plan (LP-107 Phases 3-7)

* **Phase 3 — `lattice` consumes `math`.** `lattice/ring/SubRing.NTT`
  rewires to delegate to `math/ntt`. Pulsar / Lens / FHE see no
  source change at first; v0.2.0 deprecates direct `lattice/ring`
  imports for new code.
* **Phase 4 — `pulsar` consumes `lattice` + `math`.** Drop ad-hoc
  Montgomery code; consume `math/modarith`.
* **Phase 5 — `fhe` consumes `math`.** Share NTT/RNS primitives with
  Pulsar where parameter-compatible.
* **Phase 6 — `luxcpp/crypto/math`** mirrors the Go module structure
  and becomes the native backend for `math/ntt`, `math/poly`,
  `math/sample`. KATs gate every byte across runtimes.
* **Phase 7 — Cross-runtime KAT release gate.** Go math KAT → C++
  verifies; C++ math KAT → Go verifies; GPU math KAT → CPU verifies.

## Design references

* [`LP-107`](../lps/LP-107-lux-math-substrate.md) — full spec.
* [`lattice/v7/ring`](https://github.com/luxfi/lattice/tree/main/ring)
  — canonical Lattigo-derived NTT/Montgomery body that this module
  delegates to.
* [`luxcpp/crypto/ringtail`](https://github.com/luxcpp/crypto/tree/main/ringtail)
  — native C++ Montgomery NTT that Phase 6 mirrors as `math` C++.
