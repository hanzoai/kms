package kms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func newTestLease(base, holder string) *writerLease {
	return newWriterLeaseWith(base, "hanzo", "kms-luxfi-writer", holder, 15*time.Second, http.DefaultClient, "test-token")
}

// TestWriterLeaseAcquireRenewTakeover (HIGH-3) walks the fence decision through
// create → renew → foreign-fresh(refuse) → foreign-expired(takeover).
func TestWriterLeaseAcquireRenewTakeover(t *testing.T) {
	api := &fakeLeaseAPI{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	ctx := context.Background()
	a := newTestLease(srv.URL, "kms-luxfi-0")

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

	a := newTestLease(srv.URL, "kms-luxfi-0")
	b := newTestLease(srv.URL, "kms-luxfi-1")

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

	l := newTestLease(base, "kms-luxfi-0")
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

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func strPtr(s string) *string { return &s }
