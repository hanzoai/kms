package kms

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestReadyzGatesOnHydrate (MEDIUM-2) proves liveness and readiness are
// decoupled: /healthz is 200 while the process is up, but /readyz is 503 until
// the hydrate predicate reports true — so K8s withholds traffic/promotion from
// a node still restoring from S3, without CrashLooping it on the liveness probe.
func TestReadyzGatesOnHydrate(t *testing.T) {
	var hydrated atomic.Bool
	mux := http.NewServeMux()
	registerHealth(mux, roleFollower, hydrated.Load)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	get := func(path string) (int, map[string]any) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}

	// Liveness is up immediately regardless of hydrate.
	if code, _ := get("/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz before hydrate = %d, want 200 (liveness must not gate on hydrate)", code)
	}
	// Not ready until hydrated.
	if code, body := get("/readyz"); code != http.StatusServiceUnavailable || body["hydrated"] != false {
		t.Fatalf("/readyz before hydrate = %d hydrated=%v, want 503 hydrated=false", code, body["hydrated"])
	}

	hydrated.Store(true)

	if code, body := get("/readyz"); code != http.StatusOK || body["hydrated"] != true {
		t.Fatalf("/readyz after hydrate = %d hydrated=%v, want 200 hydrated=true", code, body["hydrated"])
	}
	// Liveness still fine.
	if code, _ := get("/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz after hydrate = %d, want 200", code)
	}
}

// TestReadyzNilPredicateAlwaysReady covers the single-node/test caller that
// passes ready=nil (no replication) — always ready.
func TestReadyzNilPredicateAlwaysReady(t *testing.T) {
	mux := http.NewServeMux()
	registerHealth(mux, rolePrimary, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/readyz with nil predicate = %d, want 200", resp.StatusCode)
	}
}

// TestCanPushGate (MEDIUM-2 + HIGH-3) proves the primary push gate is
// fail-closed on BOTH hydrate and the writer fence: a push happens only when
// hydrated AND (no fence OR fence held).
func TestCanPushGate(t *testing.T) {
	held := &writerLease{}
	held.held.Store(true)
	notHeld := &writerLease{} // Held() == false

	cases := []struct {
		name     string
		hydrated bool
		fence    *writerLease
		want     bool
	}{
		{"not hydrated, no fence", false, nil, false},
		{"hydrated, no fence", true, nil, true},
		{"hydrated, fence held", true, held, true},
		{"hydrated, fence NOT held", true, notHeld, false},
		{"not hydrated, fence held", false, held, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var h atomic.Bool
			h.Store(c.hydrated)
			if got := canPush(&h, c.fence); got != c.want {
				t.Fatalf("canPush(hydrated=%v, fence=%v) = %v, want %v", c.hydrated, c.fence != nil, got, c.want)
			}
		})
	}
}
