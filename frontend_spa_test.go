// Tests for the SPA catch-all handler (registerFrontend). The critical
// invariant: /api/ is NOT a KMS surface, so the catch-all must 404 it
// rather than answer with index.html (200). Without that guard, a GET to
// /api/v1/... falls through to the React-Router fallback and returns 200,
// masquerading as a live legacy /api/ backend — the exact false positive
// that made kms.hanzo.ai look like it still served /api/v1/*. The ONE
// canonical prefix is /v1/kms; there is no /api/, and the wire must say so.
package kms

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// newSPATestServer builds a mux with the frontend catch-all active against
// a temp dir that holds a real index.html + one concrete asset, so both the
// SPA-fallback and static-file branches are exercised.
func newSPATestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>kms</title>"), 0o600); err != nil {
		t.Fatalf("write index.html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log('kms')"), 0o600); err != nil {
		t.Fatalf("write app.js: %v", err)
	}
	t.Setenv("KMS_FRONTEND_DIR", dir)

	mux := http.NewServeMux()
	registerHealth(mux)
	registerFrontend(mux)

	srv := httptest.NewServer(mux)
	return srv, srv.Close
}

func TestSPA_NoApiSurface(t *testing.T) {
	srv, cleanup := newSPATestServer(t)
	defer cleanup()

	// /api/ in any shape must 404 — never the SPA 200. This is the core
	// "there is no /api/" guarantee at the wire.
	apiPaths := []string{
		"/api",
		"/api/",
		"/api/v1/auth/universal-auth/login",
		"/api/v1/secrets",
		"/api/status/health",
		"/api/anything/at/all",
	}
	for _, p := range apiPaths {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		body := resp.StatusCode
		resp.Body.Close()
		if body != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (no /api/ surface exists)", p, body)
		}
	}
}

func TestSPA_ApiRouteBailoutsStay404(t *testing.T) {
	srv, cleanup := newSPATestServer(t)
	defer cleanup()

	// Defense-in-depth bail-outs: these never reach the SPA fallback.
	for _, p := range []string{"/v1/kms/anything", "/health"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		code := resp.StatusCode
		resp.Body.Close()
		if code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
	// /healthz has a real handler (registerHealth) — must be 200, proving
	// the more-specific route wins over the catch-all.
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	code := resp.StatusCode
	resp.Body.Close()
	if code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200", code)
	}
}

func TestSPA_ClientRoutesServeIndex(t *testing.T) {
	srv, cleanup := newSPATestServer(t)
	defer cleanup()

	// Real client-side routes and the root still get index.html (200) so
	// React Router works. This proves the /api/ 404 guard did not break the
	// legitimate SPA fallback.
	for _, p := range []string{"/", "/login", "/dashboard", "/keys"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		code := resp.StatusCode
		resp.Body.Close()
		if code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 (SPA fallback)", p, code)
		}
	}

	// Concrete on-disk asset is served directly.
	resp, err := http.Get(srv.URL + "/app.js")
	if err != nil {
		t.Fatalf("GET /app.js: %v", err)
	}
	code := resp.StatusCode
	resp.Body.Close()
	if code != http.StatusOK {
		t.Errorf("GET /app.js = %d, want 200 (static asset)", code)
	}
}
