package kms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestEmbed asserts the public Embed() entry point boots a working
// KMS server (in-memory ZapDB, dev-mode auth, no listener) and the
// returned HTTPHandler answers /healthz with 200.
//
// Runs in <2s with no external services. Mirrors the iam.Embed()
// shape so a future fused hanzo binary can call Embed() the same way
// for both services.
func TestEmbed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping kms.Embed live test in -short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	em, err := Embed(ctx, EmbedConfig{
		DataDir:    filepath.Join(t.TempDir(), "kms"),
		AuditDB:    filepath.Join(t.TempDir(), "audit.db"),
		Env:        "dev", // skips JWT-config validation
		SkipListen: true,  // mount via httptest.Server
		ZAPPort:    -1,    // disable ZAP (no master key in env)
	})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		if err := em.Stop(stopCtx); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})

	srv := httptest.NewServer(em.HTTPHandler())
	t.Cleanup(srv.Close)

	t.Run("healthz", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /healthz: status %d, want 200", resp.StatusCode)
		}
	})

	t.Run("v1_kms_health", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/kms/health")
		if err != nil {
			t.Fatalf("GET /v1/kms/health: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/kms/health: status %d, want 200", resp.StatusCode)
		}
	})

	t.Run("secret_route_requires_auth", func(t *testing.T) {
		// Sanity check: even though Env=dev tolerates missing JWT config
		// at boot, every secret route still demands a verified bearer
		// token at request time. Unauthenticated → 401.
		resp, err := http.Get(srv.URL + "/v1/kms/orgs/hanzo/secrets/foo/bar")
		if err != nil {
			t.Fatalf("GET secrets: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated GET: status %d, want 401", resp.StatusCode)
		}
	})

	t.Run("stop_is_idempotent", func(t *testing.T) {
		// Stop twice in a row must not panic or leak goroutines.
		ctx1, c1 := context.WithTimeout(context.Background(), time.Second)
		defer c1()
		if err := em.Stop(ctx1); err != nil {
			t.Errorf("first Stop: %v", err)
		}
		ctx2, c2 := context.WithTimeout(context.Background(), time.Second)
		defer c2()
		if err := em.Stop(ctx2); err != nil {
			t.Errorf("second Stop: %v", err)
		}
	})
}
