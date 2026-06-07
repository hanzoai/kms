package kms

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	badger "github.com/luxfi/zapdb"

	"github.com/luxfi/kms/pkg/store"
)

// newTestServer wires the same handlers as main() against an in-memory
// ZapDB, so we can exercise the routing + auth without booting the binary.
func newTestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "kms")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := badger.Open(badger.DefaultOptions(dir).WithLogger(nil))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	secStore := store.NewSecretStore(db)

	mux := http.NewServeMux()
	registerHealth(mux)
	registerSecretRoutes(mux, secStore, db)

	srv := httptest.NewServer(methodAllowlist(stripIdentityHeaders(mux)))
	return srv, func() { srv.Close(); db.Close() }
}

// mintToken builds a properly signed RS256 JWT using the shared test JWKS
// keypair. Post-Red-Part-5 KMS requires full JWT verification — unsigned
// tokens return 401. Callers that want cross-env or expired tokens should
// use mintTestJWTSigned directly.
func mintToken(t *testing.T, owner, sub string, roles ...string) string {
	t.Helper()
	claims := jwt.MapClaims{"owner": owner, "sub": sub}
	if len(roles) > 0 {
		claims["roles"] = roles
	}
	return mintTestJWTSigned(t, claims)
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

func TestSecretRoundTrip_Canonical(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	tok := mintToken(t, "hanzo", "user-1")

	body, _ := json.Marshal(map[string]string{
		"path":  "providers/alpaca/dev",
		"name":  "api_key",
		"env":   "dev",
		"value": "PK_LIVE",
	})
	req, _ := http.NewRequest("POST", srv.URL+"/v1/kms/orgs/hanzo/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("PUT want 201, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET",
		srv.URL+"/v1/kms/orgs/hanzo/secrets/providers/alpaca/dev/api_key?env=dev", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("GET want 200, got %d", resp.StatusCode)
	}
	var got map[string]map[string]string
	json.NewDecoder(resp.Body).Decode(&got)
	if got["secret"]["value"] != "PK_LIVE" {
		t.Fatalf("want PK_LIVE, got %q", got["secret"]["value"])
	}
}

func TestUnauthorized(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	resp, _ := http.Get(srv.URL + "/v1/kms/orgs/hanzo/secrets/foo/bar")
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestStripIdentityHeaders(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	body, _ := json.Marshal(map[string]string{
		"path": "x", "name": "y", "env": "dev", "value": "v",
	})
	req, _ := http.NewRequest("POST", srv.URL+"/v1/kms/orgs/hanzo/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	// Canonical 3 — stripped.
	req.Header.Set("X-User-Id", "attacker")
	req.Header.Set("X-Org-Id", "evil-org")
	req.Header.Set("X-Roles", "admin")
	// Every legacy variant — stripped. If any of these survived into the
	// handler, the request would be misauthorized as an admin in a foreign org.
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
	if resp.StatusCode != 201 {
		t.Fatalf("PUT want 201, got %d", resp.StatusCode)
	}
}

// --- Red-fix regression tests ---

// R-01 (CRITICAL): cross-tenant read via JWT owner mismatch.
// A token issued for org A must NOT be able to access org B's URL.
func TestRed1_CrossTenantBlocked(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	// Org A seeds a secret.
	tokA := mintToken(t, "org-a", "user-a")
	body, _ := json.Marshal(map[string]string{
		"path": "shared", "name": "key", "env": "dev", "value": "A-SECRET",
	})
	req, _ := http.NewRequest("POST", srv.URL+"/v1/kms/orgs/org-a/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokA)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 201 {
		t.Fatalf("seed want 201, got %d", resp.StatusCode)
	}

	// Org B's token tries to read org-a's URL.
	tokB := mintToken(t, "org-b", "user-b")
	req, _ = http.NewRequest("GET", srv.URL+"/v1/kms/orgs/org-a/secrets/shared/key?env=dev", nil)
	req.Header.Set("Authorization", "Bearer "+tokB)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("cross-tenant read: want 403, got %d", resp.StatusCode)
	}

	// Cross-tenant write (POST) blocked.
	body, _ = json.Marshal(map[string]string{"path": "shared", "name": "key", "value": "POISON"})
	req, _ = http.NewRequest("POST", srv.URL+"/v1/kms/orgs/org-a/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokB)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("cross-tenant write: want 403, got %d", resp.StatusCode)
	}

	// Super-admin bypass works.
	tokAdmin := mintToken(t, "ops", "admin-1", "superadmin")
	req, _ = http.NewRequest("GET", srv.URL+"/v1/kms/orgs/org-a/secrets/shared/key?env=dev", nil)
	req.Header.Set("Authorization", "Bearer "+tokAdmin)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("admin bypass: want 200, got %d", resp.StatusCode)
	}
}

// R-02 (CRITICAL): /v1/kms/secrets/{name} env-var read must require admin.
// Without a role claim a tenant must not be able to read DEPLOYER_PRIVATE_KEY.
func TestRed2_EnvVarReadRequiresAdmin(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	t.Setenv("KMS_TEST_DEPLOYER_KEY", "0xDEADBEEF")

	// Tenant token — must be denied.
	tok := mintToken(t, "hanzo", "user-1")
	req, _ := http.NewRequest("GET", srv.URL+"/v1/kms/secrets/KMS_TEST_DEPLOYER_KEY", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("env read without admin: want 403, got %d", resp.StatusCode)
	}

	// Missing auth = 401, not 200.
	req, _ = http.NewRequest("GET", srv.URL+"/v1/kms/secrets/KMS_TEST_DEPLOYER_KEY", nil)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("env read without auth: want 401, got %d", resp.StatusCode)
	}

	// Admin can read.
	admin := mintToken(t, "ops", "admin", "superadmin")
	req, _ = http.NewRequest("GET", srv.URL+"/v1/kms/secrets/KMS_TEST_DEPLOYER_KEY", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("env read with admin: want 200, got %d", resp.StatusCode)
	}

	// Invalid env-name (path-injection attempt) → 400.
	req, _ = http.NewRequest("GET", srv.URL+"/v1/kms/secrets/..%2Fetc%2Fpasswd", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 400 && resp.StatusCode != 404 {
		t.Fatalf("malicious env name: want 400/404, got %d", resp.StatusCode)
	}
}

// R-03 (HIGH): path traversal via {rest...}.
func TestRed3_PathTraversalBlocked(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	cases := []string{
		"/v1/kms/orgs/hanzo/secrets/../etc/passwd",
		"/v1/kms/orgs/hanzo/secrets/foo/..",
		"/v1/kms/orgs/hanzo/secrets/foo//bar",
		"/v1/kms/orgs/hanzo/secrets/foo/bar%00",
	}
	for _, p := range cases {
		req, _ := http.NewRequest("GET", srv.URL+p, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 400 && resp.StatusCode != 404 {
			// 404 is acceptable when net/http normalizes the path so it
			// never reaches our handler. What's NOT acceptable is 200.
			body, _ := readBody(resp)
			if strings.Contains(body, "secret") {
				t.Fatalf("%s: returned a secret payload, status=%d", p, resp.StatusCode)
			}
		}
	}
}

// R-04 (MEDIUM): TRACE/CONNECT/OPTIONS rejected at the edge.
func TestRed4_MethodAllowlist(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	for _, m := range []string{http.MethodTrace, http.MethodOptions} {
		req, _ := http.NewRequest(m, srv.URL+"/v1/kms/orgs/hanzo/secrets/x/y", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s: want 405, got %d", m, resp.StatusCode)
		}
	}
}

// R-07 (LOW): POST body capped at maxBodyBytes.
func TestRed7_PostBodyCap(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	// 2 MiB body — exceeds 1 MiB cap.
	huge := bytes.Repeat([]byte("A"), (maxBodyBytes*2)+8)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/kms/orgs/hanzo/secrets", bytes.NewReader(huge))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	// Either 400 (json decode fails on truncated input) or 413; never 201.
	if resp.StatusCode == http.StatusCreated {
		t.Fatalf("oversize body accepted: status=%d", resp.StatusCode)
	}
}

// safePath unit coverage — the function gates everything.
func TestSafePath(t *testing.T) {
	good := []string{"", "foo", "foo/bar", "providers/alpaca/dev/api_key", "a-b_c.d"}
	bad := []string{"..", "foo/..", "../etc", "foo//bar", "foo/\x00bar", "foo/$x", "foo/ bar"}
	for _, g := range good {
		if !safePath(g) {
			t.Errorf("safePath(%q) want true", g)
		}
	}
	for _, b := range bad {
		if safePath(b) {
			t.Errorf("safePath(%q) want false", b)
		}
	}
}

func TestSafeEnvName(t *testing.T) {
	good := []string{"FOO", "FOO_BAR", "_X", "X1", "ats_settlement_key"}
	bad := []string{"", "1FOO", "FOO-BAR", "FOO/BAR", "FOO BAR", "../X"}
	for _, g := range good {
		if !safeEnvName(g) {
			t.Errorf("safeEnvName(%q) want true", g)
		}
	}
	for _, b := range bad {
		if safeEnvName(b) {
			t.Errorf("safeEnvName(%q) want false", b)
		}
	}
}

func readBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	return buf.String(), err
}
