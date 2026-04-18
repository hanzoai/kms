package handler

import (
	"sync"
	"time"
)

// Small in-process idempotency cache for rotate endpoints. TTL 1h — enough
// to absorb client retries without persisting state. Process-local; horizontal
// rotation deduping is left to upstream gateways.
var (
	idempotencyMu    sync.Mutex
	idempotencyCache = map[string]time.Time{}
)

// idempotencyTTL is how long a key survives in the cache.
const idempotencyTTL = time.Hour

func idempotencyLoad(key string) (bool, time.Time) {
	idempotencyMu.Lock()
	defer idempotencyMu.Unlock()
	gcIdempotency()
	t, ok := idempotencyCache[key]
	return ok, t
}

func idempotencyStore(key string) {
	idempotencyMu.Lock()
	defer idempotencyMu.Unlock()
	gcIdempotency()
	idempotencyCache[key] = time.Now()
}

func gcIdempotency() {
	cutoff := time.Now().Add(-idempotencyTTL)
	for k, t := range idempotencyCache {
		if t.Before(cutoff) {
			delete(idempotencyCache, k)
		}
	}
}
