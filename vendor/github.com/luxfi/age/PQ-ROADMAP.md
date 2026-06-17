# Post-Quantum Roadmap

## Two KEMs, Both First-Class

luxfi/age supports two hybrid post-quantum KEMs. Callers choose at runtime.

### 1. HPKE ML-KEM-768 + X25519 (shipped v1.3.0+)

- **Type**: `HybridRecipient` / `HybridIdentity` in `pq.go`
- **Algorithm**: ML-KEM-768 + X25519 via `filippo.io/hpke` MLKEM768X25519 suite
- **Stanza type**: `mlkem768x25519`
- **Key prefix**: `age1pq1` (Bech32)
- **Label**: `"age-encryption.org/mlkem768x25519"`
- **When to use**: compatibility with existing keys, audited via FiloSottile age v1.3.0+

### 2. X-Wing (IETF draft-connolly-cfrg-xwing-kem-10)

- **Type**: `XWingRecipient` / `XWingIdentity` in `xwing.go`
- **Algorithm**: ML-KEM-768 + X25519 with SHA3-256 combiner + 6-byte XWingLabel
- **Stanza type**: `xwing`
- **Key prefix**: `age1xw1` (Bech32)
- **Label**: `"age-encryption.org/xwing"`
- **When to use**: smaller code path, official IETF draft, simpler combiner, planned for FIPS hybrid mode

## Configurable KEM Selection (REQUIRED)

### A. Auto-detect from key prefix

```go
// Zero-config: prefix determines KEM
r, _ := age.ParseRecipient("age1pq1...")  // -> HybridRecipient (HPKE MLKEM768X25519)
r, _ := age.ParseRecipient("age1xw1...")  // -> XWingRecipient (real X-Wing)
```

### B. Env var for default keygen

```
ENCRYPTION_KEM=hpke-mlkem768x25519|xwing   # default: xwing for new keys
```

CLI flags:
```bash
age-keygen --pq          # uses ENCRYPTION_KEM or default (xwing)
age-keygen --pq=hpke     # force HPKE MLKEM768X25519
age-keygen --pq=xwing    # force X-Wing
```

### C. Programmatic API

```go
import "github.com/luxfi/age"

type PQKemType string
const (
    PQKemHPKEMLKEM768X25519 PQKemType = "hpke-mlkem768x25519"
    PQKemXWing              PQKemType = "xwing"
)

// New: select KEM at keygen
identity, _ := age.GeneratePQIdentity(age.PQKemXWing)

// Existing: unchanged, backward compat (HPKE MLKEM768X25519)
identity, _ := age.GenerateHybridIdentity()
```

### D. Replicate sidecar config

```
REPLICATE_AGE_RECIPIENT=age1xw1...              # auto-detects from prefix
REPLICATE_KEM_PREFERENCE=xwing|hpke              # optional, for new key generation
REPLICATE_AGE_RECIPIENTS_FALLBACK=age1pq1...     # comma-separated, multi-recipient migration
```

### E. Operator CRD

```yaml
apiVersion: example.com/v1
kind: Replicate
spec:
  encryption:
    kem: xwing                    # enum: hpke-mlkem768x25519 | xwing
    recipients:                   # multiple supported
      - age1xw1...
      - age1pq1...               # encrypt to both during migration
```

## Migration Path

Encrypt to BOTH recipient types simultaneously during transition:

```bash
age -r age1pq1aaa... -r age1xw1bbb... -o file.age plaintext
```

Decryption tries each available identity until one works. No special code needed.

1. Generate new X-Wing keys alongside existing HPKE keys
2. Encrypt to both recipients (multi-recipient)
3. Once all consumers have X-Wing identities, drop HPKE recipients
4. Old archives remain decryptable as long as HPKE identity is retained

## Security

- **Harvest-now-decrypt-later safe**: both KEMs use ML-KEM-768 against future quantum computers
- **Hybrid**: if ML-KEM is broken, X25519 still provides classical security
- **Anonymous**: attacker can't tell which recipient a message is encrypted to
- **Label enforcement**: PQ recipients can only be mixed with other PQ recipients (prevents downgrade)

## References

- LP-102: Encrypted SQLite Replication Standard
- NIST FIPS 203 (ML-KEM) — finalized August 2024
- IETF draft-connolly-cfrg-xwing-kem-10 — X-Wing hybrid KEM
- `filippo.io/hpke` — HPKE with ML-KEM-768 + X25519
