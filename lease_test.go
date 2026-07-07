package kms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLeaseAPI is a minimal stateful stand-in for the coordination.k8s.io/v1
// Lease REST endpoint: GET (200/404), POST create (201/409-if-exists), PUT
// update (200 / 409-on-stale-resourceVersion / 404). The resourceVersion
// optimistic-concurrency is real, so it exercises the actual mutual-exclusion.
type fakeLeaseAPI struct {
	mu    sync.Mutex
	obj   *leaseObject
	rv    int
	calls int
}

func (f *fakeLeaseAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		isItem := strings.Contains(r.URL.Path, "/leases/")
		switch r.Method {
		case http.MethodGet:
			if f.obj == nil {
				http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
				return
			}
			f.writeObj(w, http.StatusOK)
		case http.MethodPost:
			if f.obj != nil {
				http.Error(w, `{"code":409}`, http.StatusConflict)
				return
			}
			var in leaseObject
			_ = json.NewDecoder(r.Body).Decode(&in)
			f.rv++
			in.Metadata.ResourceVersion = strconv.Itoa(f.rv)
			f.obj = &in
			f.writeObj(w, http.StatusCreated)
		case http.MethodPut:
			if !isItem || f.obj == nil {
				http.Error(w, `{"code":404}`, http.StatusNotFound)
				return
			}
			var in leaseObject
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Metadata.ResourceVersion != f.obj.Metadata.ResourceVersion {
				http.Error(w, `{"code":409}`, http.StatusConflict) // stale write loses
				return
			}
			f.rv++
			in.Metadata.ResourceVersion = strconv.Itoa(f.rv)
			f.obj = &in
			f.writeObj(w, http.StatusOK)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
}

func (f *fakeLeaseAPI) writeObj(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(f.obj)
}

func (f *fakeLeaseAPI) seed(holder string, renew time.Time, durSecs int32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rv++
	rs := renew.UTC().Format(time.RFC3339Nano)
	f.obj = &leaseObject{
		APIVersion: "coordination.k8s.io/v1", Kind: "Lease",
		Metadata: leaseMeta{Name: "kms-luxfi-writer", Namespace: "hanzo", ResourceVersion: strconv.Itoa(f.rv)},
		Spec:     leaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &durSecs, RenewTime: &rs, LeaseTransitions: int32Ptr(3)},
	}
}

func (f *fakeLeaseAPI) holder() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.obj == nil || f.obj.Spec.HolderIdentity == nil {
		return ""
	}
	return *f.obj.Spec.HolderIdentity
}

// newTestLease writes the bearer token to a real file (the writer lease now
// re-reads its token from disk each request, so tests must exercise that path
// rather than inject a constant string).
func newTestLease(t *testing.T, base, holder string) *writerLease {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return newWriterLeaseWith(base, "hanzo", "kms-luxfi-writer", holder, 15*time.Second, http.DefaultClient, tokenPath)
}

// TestWriterLeaseAcquireRenewTakeover (HIGH-3) walks the fence decision through
// create → renew → foreign-fresh(refuse) → foreign-expired(takeover).
func TestWriterLeaseAcquireRenewTakeover(t *testing.T) {
	api := &fakeLeaseAPI{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	ctx := context.Background()
	a := newTestLease(t, srv.URL, "kms-luxfi-0")

	// 1. absent → create → held.
	if held, err := a.acquireOrRenew(ctx); err != nil || !held {
		t.Fatalf("create: held=%v err=%v, want held=true", held, err)
	}
	if api.holder() != "kms-luxfi-0" {
		t.Fatalf("holder=%q, want kms-luxfi-0", api.holder())
	}

	// 2. mine, fresh → renew → still held.
	if held, err := a.acquireOrRenew(ctx); err != nil || !held {
		t.Fatalf("renew: held=%v err=%v, want held=true", held, err)
	}

	// 3. another holder, still fresh → we must fence ourselves.
	api.seed("kms-luxfi-1", time.Now(), 15)
	if held, err := a.acquireOrRenew(ctx); err != nil || held {
		t.Fatalf("foreign-fresh: held=%v err=%v, want held=false (fenced)", held, err)
	}
	if api.holder() != "kms-luxfi-1" {
		t.Fatalf("a fresh foreign lease must not be overwritten; holder=%q", api.holder())
	}

	// 4. that holder's lease expired → we take over.
	api.seed("kms-luxfi-1", time.Now().Add(-time.Hour), 15)
	if held, err := a.acquireOrRenew(ctx); err != nil || !held {
		t.Fatalf("takeover-expired: held=%v err=%v, want held=true", held, err)
	}
	if api.holder() != "kms-luxfi-0" {
		t.Fatalf("after takeover holder=%q, want kms-luxfi-0", api.holder())
	}
}

// TestWriterLeaseMutualExclusion (HIGH-3) proves two nodes cannot both hold the
// lease: on a contended expired lease, exactly one PUT wins and the other
// 409-conflicts and fences itself.
func TestWriterLeaseMutualExclusion(t *testing.T) {
	api := &fakeLeaseAPI{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	ctx := context.Background()
	api.seed("dead-primary", time.Now().Add(-time.Hour), 15) // expired, up for grabs

	a := newTestLease(t, srv.URL, "kms-luxfi-0")
	b := newTestLease(t, srv.URL, "kms-luxfi-1")

	// Both observe the same (stale) resourceVersion, then both try to take over.
	curA, _, err := a.get(ctx)
	mustNoErr(t, err)
	curB, _, err := b.get(ctx)
	mustNoErr(t, err)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, c := range []*leaseObject{curA, curB} {
		c.Spec.RenewTime = &now
		c.Spec.LeaseDurationSeconds = int32Ptr(15)
	}
	*curA.Spec.HolderIdentity = "kms-luxfi-0"
	*curB.Spec.HolderIdentity = "kms-luxfi-1"

	heldA, errA := a.update(ctx, curA)
	heldB, errB := b.update(ctx, curB)
	mustNoErr(t, errA)
	mustNoErr(t, errB)
	if heldA == heldB {
		t.Fatalf("exactly one writer must win the takeover; got heldA=%v heldB=%v", heldA, heldB)
	}
}

// TestWriterLeaseFailsClosed (HIGH-3) proves an unreachable API server yields an
// error (→ tick drops Held to false), never a silent held=true.
func TestWriterLeaseFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close() // now unreachable

	l := newTestLease(t, base, "kms-luxfi-0")
	l.held.Store(true) // pretend we held it
	l.tick(context.Background())
	if l.Held() {
		t.Fatal("writer fence must fail CLOSED when the API is unreachable (Held stayed true)")
	}
}

func TestLeaseExpired(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Format(time.RFC3339Nano)
	stale := now.Add(-time.Hour).Format(time.RFC3339Nano)
	d := int32Ptr(15)
	cases := []struct {
		name string
		o    *leaseObject
		want bool
	}{
		{"nil renewTime", &leaseObject{Spec: leaseSpec{LeaseDurationSeconds: d}}, true},
		{"unparseable", &leaseObject{Spec: leaseSpec{RenewTime: strPtr("nope"), LeaseDurationSeconds: d}}, true},
		{"fresh", &leaseObject{Spec: leaseSpec{RenewTime: &fresh, LeaseDurationSeconds: d}}, false},
		{"stale", &leaseObject{Spec: leaseSpec{RenewTime: &stale, LeaseDurationSeconds: d}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := leaseExpired(c.o, now); got != c.want {
				t.Fatalf("leaseExpired=%v, want %v", got, c.want)
			}
		})
	}
}

// TestWriterLeaseRereadsRotatedToken (Fix 1) proves the writer lease re-reads
// its ServiceAccount token from disk on EVERY request, so a kubelet token
// rotation is picked up in place. A value cached at construction (the prior
// behaviour) would keep sending the OLD token until the API 401'd the primary
// into a SILENT self-fence — replication halts while /readyz stays green. Red's
// constant "test-token" could not catch this; a rotating file can.
func TestWriterLeaseRereadsRotatedToken(t *testing.T) {
	var mu sync.Mutex
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Get("Authorization")
		mu.Unlock()
		http.Error(w, `{"code":404}`, http.StatusNotFound) // status is irrelevant; we assert the header
	}))
	defer srv.Close()
	lastSeen := func() string { mu.Lock(); defer mu.Unlock(); return seen }

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("token-v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newWriterLeaseWith(srv.URL, "hanzo", "kms-luxfi-writer", "kms-luxfi-0", 15*time.Second, srv.Client(), tokenPath)

	if _, _, err := l.get(context.Background()); err != nil {
		t.Fatalf("get v1: %v", err)
	}
	if got := lastSeen(); got != "Bearer token-v1" {
		t.Fatalf("first request Authorization=%q, want %q", got, "Bearer token-v1")
	}

	// kubelet rotates the projected token in place.
	if err := os.WriteFile(tokenPath, []byte("token-v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.get(context.Background()); err != nil {
		t.Fatalf("get v2: %v", err)
	}
	if got := lastSeen(); got != "Bearer token-v2" {
		t.Fatalf("after rotation Authorization=%q, want %q (token must be re-read from disk)", got, "Bearer token-v2")
	}

	// Fail-closed: a vanished token file must ERROR (drives the tick to drop
	// Held) rather than send a blank bearer.
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.get(context.Background()); err == nil {
		t.Fatal("get with a missing token file must fail closed (error), not send an empty bearer")
	}
}

// TestWriterLeaseHeldUntilDeadline (Fix 3) proves the push gate fences a zombie
// primary whose renew loop was STW-paused past the lease duration: even with the
// cached held flag still true, Held() is false once the monotonic validity
// deadline has lapsed — so no post-pause push slips through before the next
// (failing) renew tick runs.
func TestWriterLeaseHeldUntilDeadline(t *testing.T) {
	l := newTestLease(t, "http://127.0.0.1:1", "kms-luxfi-0")
	l.held.Store(true)

	future := time.Now().Add(10 * time.Second)
	l.heldUntil.Store(&future)
	if !l.Held() {
		t.Fatal("Held must be true while within the renew validity window")
	}

	// Simulate a STW pause past the lease duration: the deadline is now in the
	// past while the cached flag is still true (the failing tick hasn't run).
	past := time.Now().Add(-time.Second)
	l.heldUntil.Store(&past)
	if l.Held() {
		t.Fatal("Held must be FALSE once the validity deadline has lapsed, even with held=true (zombie-primary push window)")
	}

	// A nil deadline (never successfully renewed) is never held.
	l.heldUntil.Store(nil)
	if l.Held() {
		t.Fatal("Held must be false with no recorded renew deadline")
	}
}

// TestWriterLeaseTickSetsDeadline (Fix 3) proves a successful tick records a
// fresh, future validity deadline so Held() — which now gates on it — reports
// true on the healthy path. Exercises the file-backed token (Fix 1) too.
func TestWriterLeaseTickSetsDeadline(t *testing.T) {
	api := &fakeLeaseAPI{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	l := newTestLease(t, srv.URL, "kms-luxfi-0")

	l.tick(context.Background())
	if !l.Held() {
		t.Fatal("after a successful tick the primary must hold a fresh, in-window lease")
	}
	if u := l.heldUntil.Load(); u == nil || !time.Now().Before(*u) {
		t.Fatalf("tick must record a future validity deadline; got %v", u)
	}
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func strPtr(s string) *string { return &s }
