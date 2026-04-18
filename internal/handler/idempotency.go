package handler

import (
	"sync"
	"time"
)

// In-process idempotency cache for rotate endpoints. TTL 1h — enough to
// absorb client retries without persisting state. Process-local; horizontal
// rotation deduping is left to upstream gateways.
//
// F8: Keys are scoped by (tenantID, secretID, rawKey). Without this scoping,
// a client-supplied `Idempotency-Key` from tenant A could match a replay from
// tenant B and incorrectly short-circuit a real rotation.
//
// F9: ClaimOnce is the atomic "SETNX" primitive — returns true only if the
// caller is the first to claim the key; concurrent callers lose the race and
// get false. Callers must not rotate if ClaimOnce returns false.
var (
	idempotencyMu    sync.Mutex
	idempotencyCache = map[string]time.Time{}
)

// idempotencyTTL is how long a key survives in the cache.
const idempotencyTTL = time.Hour

// buildIdempotencyKey constructs the scoped cache key. The raw client header
// is one of three components; collisions across tenants or secrets are
// impossible by construction.
func buildIdempotencyKey(tenantID, secretID, rawKey string) string {
	if rawKey == "" {
		return ""
	}
	// Use NUL as separator — it cannot appear in header values or IDs.
	return tenantID + "\x00" + secretID + "\x00" + rawKey
}

// idempotencyLoad returns (seen, firstSeenAt) for a scoped key.
func idempotencyLoad(scopedKey string) (bool, time.Time) {
	if scopedKey == "" {
		return false, time.Time{}
	}
	idempotencyMu.Lock()
	defer idempotencyMu.Unlock()
	gcIdempotency()
	t, ok := idempotencyCache[scopedKey]
	return ok, t
}

// idempotencyClaim atomically records the key IF it is not already present.
// Returns true iff this caller is the first to claim (F9 SETNX semantics).
func idempotencyClaim(scopedKey string) bool {
	if scopedKey == "" {
		return true // no key → caller is always free to proceed
	}
	idempotencyMu.Lock()
	defer idempotencyMu.Unlock()
	gcIdempotency()
	if _, exists := idempotencyCache[scopedKey]; exists {
		return false
	}
	idempotencyCache[scopedKey] = time.Now()
	return true
}

// idempotencyStore is retained for backwards-compat callers that already
// checked with idempotencyLoad and only want to record success.
func idempotencyStore(scopedKey string) {
	if scopedKey == "" {
		return
	}
	idempotencyMu.Lock()
	defer idempotencyMu.Unlock()
	gcIdempotency()
	idempotencyCache[scopedKey] = time.Now()
}

func gcIdempotency() {
	cutoff := time.Now().Add(-idempotencyTTL)
	for k, t := range idempotencyCache {
		if t.Before(cutoff) {
			delete(idempotencyCache, k)
		}
	}
}
