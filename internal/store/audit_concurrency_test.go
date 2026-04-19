package store

import (
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tests"
)

// Multiple concurrent writers to the same org_id must produce a strictly
// linearizable audit chain. The pre-fix writer could observe the same tail
// `seq=N, hash=H` as another writer, each compute hash=SHA256(H||entry_i),
// and the UNIQUE-constraint retry loop was the only thing preventing the
// second insert. Between retry and re-read a third writer could interleave,
// producing ghost-link chains where seq is monotonic but prev_hash values
// are non-causal.
//
// Post-fix: Append acquires a per-org app-layer sync.Mutex before entering
// the transaction. Paired with SQLite's write mutex (held across the tx),
// this gives linearizable tail-read → INSERT for every writer in the same
// process. The UNIQUE constraint on (org_id, seq) is the DB-level safety
// net if the mutex is ever bypassed.
func TestAuditAppend_ConcurrentWritersSameOrg_ChainLinearizable(t *testing.T) {
	app, cleanup := newAuditTestApp(t)
	defer cleanup()

	store := NewAuditStore(app)
	const writers = 5
	const perWriter = 10
	const org = "org-r3-1"

	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				entry := map[string]any{
					"writer": w,
					"seq":    i,
					"nonce":  fmt.Sprintf("%d-%d", w, i),
				}
				if err := store.Append(org, entry); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent Append returned error: %v", e)
	}

	// Pull everything back — List already calls verifyHashChain, which is
	// the exact invariant we care about. If chain is broken, List returns
	// a tamper error.
	entries, err := store.List(org)
	if err != nil {
		t.Fatalf("List returned tamper error — chain is not linearizable: %v", err)
	}
	if got, want := len(entries), writers*perWriter; got != want {
		t.Fatalf("wrote %d entries but read back %d", want, got)
	}

	// seq must be strictly 1..N with no gaps.
	seqs := make([]int, 0, len(entries))
	for _, e := range entries {
		seqs = append(seqs, e.Seq)
	}
	sort.Ints(seqs)
	for i, s := range seqs {
		if s != i+1 {
			t.Fatalf("seq gap at index %d: got %d, want %d (full seqs=%v)", i, s, i+1, seqs)
		}
	}

	// prev_hash must equal the previous entry's hash, in seq order. List
	// already sorts by seq ASC, so we can walk the slice directly. The
	// inner verifyHashChain call in List covers the same invariant; this
	// is the readable spec.
	for i, e := range entries {
		if i == 0 {
			if e.PrevHash != "" {
				t.Fatalf("seq=1 prev_hash should be empty, got %q", e.PrevHash)
			}
			continue
		}
		if e.PrevHash != entries[i-1].Hash {
			t.Fatalf("seq=%d prev_hash=%q does not match seq=%d hash=%q (non-causal link)",
				e.Seq, e.PrevHash, entries[i-1].Seq, entries[i-1].Hash)
		}
	}
}

// newAuditTestApp spins up an isolated Base test app (SQLite, migrations
// applied via tests.NewTestApp) and bootstraps the KMS audit collection.
func newAuditTestApp(t *testing.T) (core.App, func()) {
	t.Helper()
	testApp, err := tests.NewTestApp()
	if err != nil {
		t.Fatalf("tests.NewTestApp: %v", err)
	}
	if err := Bootstrap(testApp); err != nil {
		testApp.Cleanup()
		t.Fatalf("store.Bootstrap: %v", err)
	}
	return testApp, testApp.Cleanup
}
