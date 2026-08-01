package kms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

	// Stand up a fake JWKS so Embed has somewhere to point ExpectedIssuer
	// and JWKSURL. There is no permissive env any more — every Hanzo
	// user supplies these four fields or Embed refuses to boot.
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))

	// Registered BEFORE jwks.Close so it runs LAST (t.Cleanup is LIFO).
	//
	// Embed applies its ExpectedIssuer/ExpectedAudience/JWKSURL to the
	// PROCESS-GLOBAL authConfig — that is the whole point of Embed — and
	// stopping the instance does not put it back. Without this, every test
	// after TestEmbed mints tokens for sharedIssuer/sharedAudience, which the
	// process no longer accepts, and verification reaches for a JWKS server
	// this cleanup has already closed. They all 401, and none of them are
	// broken: TestEnvRequired_* were failing exactly this way, and only because
	// they happen to sort after TestEmbed.
	//
	// jwtTestEnv.cleanup already does this; the embedded path had been missed.
	t.Cleanup(func() {
		applyAuthConfig(authCfgValues{
			issuer:   sharedIssuer,
			audience: sharedAudience,
			jwksURL:  sharedJWKS.URL,
		})
		resetJWKSCacheForTest()
	})
	t.Cleanup(jwks.Close)

	em, err := Embed(ctx, EmbedConfig{
		DataDir:          filepath.Join(t.TempDir(), "kms"),
		Env:              "dev",
		IAMEndpoint:      jwks.URL,
		ExpectedIssuer:   jwks.URL,
		ExpectedAudience: "kms-test",
		JWKSURL:          jwks.URL + "/.well-known/jwks",
		SkipListen:       true, // mount via httptest.Server
		ZAPPort:          -1,   // disable ZAP (no master key in env)
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

	t.Run("no_secret_route_on_the_assembled_handler", func(t *testing.T) {
		// The end-to-end shape of the fix: a booted Embedded serves no
		// HTTP secret plane, so there is nothing to authorize. This runs
		// against em.HTTPHandler() — the same handler mount.go bridges
		// into the cloud binary — so a re-registration would fail here
		// even if it bypassed the unit-level route assembly.
		for _, p := range []string{
			"/v1/kms/orgs/hanzo/secrets/foo/bar",
			"/v1/kms/orgs/hanzo/secrets",
			"/v1/kms/secrets/KMS_MASTER_KEY_B64",
		} {
			resp, err := http.Get(srv.URL + p)
			if err != nil {
				t.Fatalf("GET %s: %v", p, err)
			}
			body, _ := readBody(resp)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s: status %d, want 404 (route absent)", p, resp.StatusCode)
			}
			if strings.Contains(body, `"value"`) || strings.Contains(body, "secretValue") {
				t.Errorf("GET %s: returned a secret payload: %s", p, body)
			}
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
