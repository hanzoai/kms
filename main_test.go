package kms

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// newTestServer wires the same handlers as main() so we can exercise the
// routing + authentication without booting the binary. registerAuthProbe
// stands in for a route behind authorize(): the KMS HTTP surface itself
// has no authenticated route left, because the secret plane it used to
// gate now lives in cloud (apps/kms), org-scoped in the storage key.
func newTestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	mux := http.NewServeMux()
	registerHealth(mux)
	registerAuthProbe(mux)

	srv := httptest.NewServer(methodAllowlist(stripIdentityHeaders(mux)))
	return srv, srv.Close
}

// mintToken builds a properly signed RS256 JWT using the shared test JWKS
// keypair. KMS requires full JWT verification — unsigned tokens return
// 401. Callers that want cross-env or expired tokens should use
// mintTestJWTSigned directly.
//
// There is no roles variant: KMS reads no `roles` claim, because it makes
// no permission decision.
func mintToken(t *testing.T, owner, sub string) string {
	t.Helper()
	return mintTestJWTSigned(t, jwt.MapClaims{"owner": owner, "sub": sub})
}

func TestHealth(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

func TestUnauthorized(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	resp, _ := http.Get(srv.URL + probePath)
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestStripIdentityHeaders(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	req, _ := http.NewRequest("GET", srv.URL+probePath, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	// Canonical 3 — stripped.
	req.Header.Set("X-User-Id", "attacker")
	req.Header.Set("X-Org-Id", "evil-org")
	req.Header.Set("X-Roles", "admin")
	// Every legacy variant — stripped. If any of these survived into the
	// handler, a downstream reader could take the request for an admin in a
	// foreign org.
	req.Header.Set("X-Hanzo-User-Id", "attacker")
	req.Header.Set("X-Hanzo-Org-Id", "evil-org")
	req.Header.Set("X-Hanzo-User-Role", "superadmin")
	req.Header.Set("X-Hanzo-User-IsAdmin", "true")
	req.Header.Set("X-IAM-User-Id", "attacker")
	req.Header.Set("X-IAM-Org", "evil-org")
	req.Header.Set("X-IAM-Roles", "superadmin")
	req.Header.Set("X-User-Role", "superadmin")
	req.Header.Set("X-User-Roles", "superadmin")
	req.Header.Set("X-Tenant-Id", "evil-org")
	req.Header.Set("X-Tenant-ID", "evil-org")
	req.Header.Set("X-Is-Admin", "true")

	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	// The identity that reached the handler is the token's, not a header's.
	body, _ := readBody(resp)
	if !bytes.Contains([]byte(body), []byte(`"user-1"`)) {
		t.Fatalf("handler saw a header-supplied identity, not the token's: %s", body)
	}
}

// The KMS HTTP secret plane is deleted, not gated.
//
// It authorized on the {org} URL segment while the ZapDB key
// (kms/secrets/{path}/{env}/{name}) carried no org, so any authenticated
// tenant could read AND overwrite any other tenant's record by naming it
// in the path — and GET /v1/kms/secrets/{name} returned any process env
// var. Both are gone; cloud (apps/kms) serves secrets over HTTP with the
// org folded into the storage key.
//
// This asserts absence, so it fails if anyone re-registers the routes
// here — including the live proof-of-concept path.
func TestSecretHTTPPlaneIsAbsent(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	// A fully valid bearer for owner=lux. Authentication is not the
	// control here — there is nothing to reach.
	tok := mintToken(t, "lux", "user-lux")

	for _, tc := range []struct{ method, path string }{
		// The live PoC: a non-admin owner=lux bearer naming hanzo's secret.
		{"GET", "/v1/kms/orgs/lux/secrets/brand/hanzo/plivo/AUTH_TOKEN"},
		{"GET", "/v1/kms/orgs/lux/secrets"},
		{"POST", "/v1/kms/orgs/lux/secrets"},
		{"PATCH", "/v1/kms/orgs/lux/secrets/brand/hanzo/plivo/AUTH_TOKEN"},
		{"DELETE", "/v1/kms/orgs/lux/secrets/brand/hanzo/plivo/AUTH_TOKEN"},
		// Env-var disclosure, including the master key.
		{"GET", "/v1/kms/secrets/KMS_MASTER_KEY_B64"},
		// Surfaces whose only gate was the roles claim IAM never mints.
		{"GET", "/v1/kms/audit/stats"},
		{"GET", "/v1/kms/keys"},
		{"GET", "/v1/kms/status"},
		{"POST", "/v1/kms/keys/generate"},
	} {
		req, _ := http.NewRequest(tc.method, srv.URL+tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: want 404 (route absent), got %d",
				tc.method, tc.path, resp.StatusCode)
		}
		body, _ := readBody(resp)
		if bytes.Contains([]byte(body), []byte(`"value"`)) ||
			bytes.Contains([]byte(body), []byte("secretValue")) {
			t.Errorf("%s %s: returned a secret payload: %s", tc.method, tc.path, body)
		}
	}
}

// TRACE/CONNECT/OPTIONS rejected at the edge.
func TestRed4_MethodAllowlist(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	for _, m := range []string{http.MethodTrace, http.MethodOptions} {
		req, _ := http.NewRequest(m, srv.URL+probePath, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s: want 405, got %d", m, resp.StatusCode)
		}
	}
}

// The login proxy is the one remaining body-taking route; its body stays
// capped at maxBodyBytes.
func TestRed7_PostBodyCap(t *testing.T) {
	mux := http.NewServeMux()
	registerAuth(mux, "http://127.0.0.1:1") // IAM unreachable: we never get that far
	srv := httptest.NewServer(methodAllowlist(stripIdentityHeaders(mux)))
	defer srv.Close()

	// 2 MiB body — exceeds the 1 MiB cap.
	huge := bytes.Repeat([]byte("A"), (maxBodyBytes*2)+8)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/kms/auth/login", bytes.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	// 400 (decode fails on truncated input) or 413; never 200.
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("oversize body accepted: status=%d", resp.StatusCode)
	}
}

func readBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	return buf.String(), err
}
