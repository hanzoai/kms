package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/base/core"
)

const (
	idempotencyCollection = "kms_idempotency"
	idempotencyTTL        = 24 * time.Hour
)

// IdempotencyStore claims idempotency keys atomically via a UNIQUE DB index.
// The first writer wins; subsequent writers for the same scoped key return
// false (already claimed). TTL is 24h — after expiry the row is ignored by
// Claim() and eventually reaped by the GC sweep.
//
// R2-7: the previous in-process map+mutex did not span replicas. Two KMS
// pods could each accept the same Idempotency-Key header and both rotate,
// with the duplicate detected only by the secret-versions UNIQUE index,
// yielding inconsistent client outcomes. Now the claim itself lives in the
// DB and survives replica scale-out.
type IdempotencyStore struct {
	app core.App
}

// NewIdempotencyStore wires the claim table.
func NewIdempotencyStore(app core.App) *IdempotencyStore {
	return &IdempotencyStore{app: app}
}

// Claim atomically inserts scopedKey. Returns (firstClaim=true) only if this
// caller was the first. Expired prior claims are overwritten.
func (s *IdempotencyStore) Claim(scopedKey string) (bool, error) {
	if scopedKey == "" {
		return true, nil // no key → caller is always free to proceed
	}

	// Best-effort GC sweep on each claim. Cheap and bounded.
	s.gc()

	col, err := s.app.FindCollectionByNameOrId(idempotencyCollection)
	if err != nil {
		return false, fmt.Errorf("idempotency: collection: %w", err)
	}
	expires := time.Now().Add(idempotencyTTL).UTC().Format(time.RFC3339)

	rec := core.NewRecord(col)
	rec.Set("scoped_key", scopedKey)
	rec.Set("expires_at", expires)
	if saveErr := s.app.Save(rec); saveErr == nil {
		return true, nil
	} else {
		emsg := saveErr.Error()
		// Not a conflict: hard fail.
		if !strings.Contains(emsg, "23505") &&
			!strings.Contains(emsg, "UNIQUE constraint failed") &&
			!strings.Contains(emsg, "duplicate key") {
			return false, fmt.Errorf("idempotency: claim: %w", saveErr)
		}
	}

	// Conflict — look at existing row. If expired, take it over (delete +
	// re-insert). Otherwise we lost the race.
	existing, err := s.app.FindFirstRecordByFilter(
		idempotencyCollection,
		"scoped_key = {:k}",
		map[string]any{"k": scopedKey},
	)
	if err != nil || existing == nil {
		// Row vanished between insert fail and read — somebody else deleted.
		// Treat as lost race; the caller can retry.
		return false, nil
	}
	if isExpired(existing.GetString("expires_at")) {
		if delErr := s.app.Delete(existing); delErr != nil {
			return false, nil
		}
		rec2 := core.NewRecord(col)
		rec2.Set("scoped_key", scopedKey)
		rec2.Set("expires_at", expires)
		if saveErr := s.app.Save(rec2); saveErr == nil {
			return true, nil
		}
		return false, nil
	}
	return false, nil
}

// gc deletes expired claims. Called opportunistically on Claim.
func (s *IdempotencyStore) gc() {
	cutoff := time.Now().UTC().Format(time.RFC3339)
	recs, err := s.app.FindRecordsByFilter(
		idempotencyCollection,
		"expires_at < {:cut}",
		"expires_at", 256, 0,
		map[string]any{"cut": cutoff},
	)
	if err != nil {
		return
	}
	for _, r := range recs {
		_ = s.app.Delete(r)
	}
}

func isExpired(ts string) bool {
	if ts == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return true
	}
	return time.Now().After(t)
}

// BuildScopedKey constructs the canonical key used by KMS handlers for the
// rotate-secret idempotency check. tenantID and secretID make the key
// tenant-safe; rawKey is the client-supplied Idempotency-Key header.
func BuildScopedKey(tenantID, secretID, rawKey string) string {
	if rawKey == "" {
		return ""
	}
	// NUL separator — cannot appear in header values or IDs.
	return tenantID + "\x00" + secretID + "\x00" + rawKey
}
