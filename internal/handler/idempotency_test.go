package handler

// Idempotency cross-tenant + atomic-claim tests (F8, F9).

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestIdempotencyScoping_CrossTenant — F8 regression. The same raw client
// header key must NOT collide across tenants or secrets.
func TestIdempotencyScoping_CrossTenant(t *testing.T) {
	rawKey := "client-shared-header"
	a := buildIdempotencyKey("tenant-A", "sec-1", rawKey)
	b := buildIdempotencyKey("tenant-B", "sec-1", rawKey)
	if a == b {
		t.Fatalf("cross-tenant scoped keys collided: %q == %q", a, b)
	}

	aa := buildIdempotencyKey("tenant-A", "sec-2", rawKey)
	if a == aa {
		t.Fatalf("cross-secret scoped keys collided: %q == %q", a, aa)
	}

	// Claim on A must not short-circuit B.
	if !idempotencyClaim(a) {
		t.Fatal("first claim on tenant-A should succeed")
	}
	if !idempotencyClaim(b) {
		t.Fatal("first claim on tenant-B should succeed (independent of tenant-A)")
	}
}

// TestIdempotencyClaim_AtomicUnderRace — F9 regression. 50 goroutines race
// for the same scoped key; exactly one must win.
func TestIdempotencyClaim_AtomicUnderRace(t *testing.T) {
	key := buildIdempotencyKey("tenant-race", "sec-race", "rot-42")

	const attempts = 50
	var winners int64
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if idempotencyClaim(key) {
				atomic.AddInt64(&winners, 1)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&winners); got != 1 {
		t.Fatalf("expected exactly 1 winner under race, got %d", got)
	}
}

// TestIdempotencyClaim_EmptyRawKey — empty raw key means "no idempotency
// requested" and must always succeed for every caller.
func TestIdempotencyClaim_EmptyRawKey(t *testing.T) {
	empty := buildIdempotencyKey("t", "s", "")
	if empty != "" {
		t.Fatalf("expected empty scoped key for empty raw, got %q", empty)
	}
	for i := 0; i < 5; i++ {
		if !idempotencyClaim(empty) {
			t.Fatalf("empty-key claim #%d failed; must always succeed", i)
		}
	}
}
