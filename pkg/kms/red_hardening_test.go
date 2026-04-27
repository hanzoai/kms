// Red-fix regression tests for R-3 (version replay protection) and
// R-12 (composite actor_id audit trail).
//
// These tests exercise the HTTP surface end-to-end — same wiring as
// production: strip-identity-headers → method-allowlist → mux → handler.
package kms

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	badger "github.com/luxfi/zapdb"

	"github.com/luxfi/kms/pkg/store"
	_ "modernc.org/sqlite"
)

// newTestServerWithAudit wires the full handler chain + an isolated
// audit DB in the test tempdir, so tests can assert on audit_log rows.
func newTestServerWithAudit(t *testing.T) (*httptest.Server, string, func()) {
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

	auditPath := filepath.Join(t.TempDir(), "audit.db")
	auditCtx, auditCancel := context.WithCancel(context.Background())
	prev := globalAuditor
	globalAuditor = newAuditor(auditCtx, auditPath)
	if globalAuditor == nil {
		t.Fatal("audit init failed")
	}

	mux := http.NewServeMux()
	registerHealth(mux)
	registerSecretRoutes(mux, secStore, db)
	srv := httptest.NewServer(methodAllowlist(stripIdentityHeaders(mux)))
	cleanup := func() {
		srv.Close()
		auditCancel()
		globalAuditor = prev
		db.Close()
	}
	return srv, auditPath, cleanup
}

// mintTokenWithIss builds a signed RS256 JWT carrying iss/owner/sub/roles.
// Post-Red-Part-5 this always signs against the shared test JWKS; the
// `iss` parameter is placed into the claim but still must equal the
// configured KMS_EXPECTED_ISSUER for verification to succeed (tests that
// exercise cross-env rejection call this with the attacker issuer and
// expect 401).
func mintTokenWithIss(t *testing.T, iss, owner, sub string, roles ...string) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": iss, "owner": owner, "sub": sub}
	if len(roles) > 0 {
		claims["roles"] = roles
	}
	return mintTestJWTSigned(t, claims)
}

// TestRed3_PatchVersionReplayProtection covers the full R-3 threat model:
//   - PATCH without version → 428
//   - PATCH with wrong version → 409
//   - PATCH with correct version → 200, version bumps
//   - Replay of old PATCH after rotation → 409
func TestRed3_PatchVersionReplayProtection(t *testing.T) {
	srv, _, cleanup := newTestServerWithAudit(t)
	defer cleanup()

	tok := mintTokenWithIss(t, sharedIssuer, "hanzo", "usr_zatsch")

	// Initial POST → version 1.
	body, _ := json.Marshal(map[string]string{
		"path": "test/replay", "name": "x", "env": "dev", "value": "v1",
	})
	req, _ := http.NewRequest("POST", srv.URL+"/v1/kms/orgs/hanzo/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 201 {
		t.Fatalf("initial POST want 201, got %d", resp.StatusCode)
	}
	var postResp struct{ Version int64 }
	json.NewDecoder(resp.Body).Decode(&postResp)
	if postResp.Version != 1 {
		t.Fatalf("initial version: want 1, got %d", postResp.Version)
	}

	// PATCH without version → 428 Precondition Required.
	patchBody, _ := json.Marshal(map[string]string{"value": "v2", "env": "dev"})
	req, _ = http.NewRequest("PATCH",
		srv.URL+"/v1/kms/orgs/hanzo/secrets/test/replay/x",
		bytes.NewReader(patchBody))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("PATCH without version: want 428, got %d", resp.StatusCode)
	}

	// PATCH with wrong version → 409 Conflict.
	patchBody, _ = json.Marshal(map[string]any{"value": "v2", "version": 99, "env": "dev"})
	req, _ = http.NewRequest("PATCH",
		srv.URL+"/v1/kms/orgs/hanzo/secrets/test/replay/x",
		bytes.NewReader(patchBody))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("PATCH with wrong version: want 409, got %d", resp.StatusCode)
	}

	// PATCH with correct version → 200, version becomes 2.
	patchBody, _ = json.Marshal(map[string]any{"value": "v2", "version": 1, "env": "dev"})
	req, _ = http.NewRequest("PATCH",
		srv.URL+"/v1/kms/orgs/hanzo/secrets/test/replay/x",
		bytes.NewReader(patchBody))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("correct PATCH: want 200, got %d", resp.StatusCode)
	}
	var okResp struct{ Version int64 }
	json.NewDecoder(resp.Body).Decode(&okResp)
	if okResp.Version != 2 {
		t.Fatalf("bumped version: want 2, got %d", okResp.Version)
	}

	// Replay original PATCH (version=1) AFTER rotation → 409.
	patchBody, _ = json.Marshal(map[string]any{"value": "v2", "version": 1, "env": "dev"})
	req, _ = http.NewRequest("PATCH",
		srv.URL+"/v1/kms/orgs/hanzo/secrets/test/replay/x",
		bytes.NewReader(patchBody))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("replayed PATCH after rotation: want 409, got %d", resp.StatusCode)
	}

	// If-Match header instead of body → also works.
	patchBody, _ = json.Marshal(map[string]string{"value": "v3", "env": "dev"})
	req, _ = http.NewRequest("PATCH",
		srv.URL+"/v1/kms/orgs/hanzo/secrets/test/replay/x",
		bytes.NewReader(patchBody))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("If-Match", "2")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("If-Match PATCH: want 200, got %d", resp.StatusCode)
	}

	// If-Match and body.version disagree → 400.
	patchBody, _ = json.Marshal(map[string]any{"value": "v4", "version": 3, "env": "dev"})
	req, _ = http.NewRequest("PATCH",
		srv.URL+"/v1/kms/orgs/hanzo/secrets/test/replay/x",
		bytes.NewReader(patchBody))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("If-Match", "99")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("conflicting If-Match/body: want 400, got %d", resp.StatusCode)
	}
}

// TestRed3_PatchRequiresExistingSecret — PATCH must not create, only update.
func TestRed3_PatchRequiresExistingSecret(t *testing.T) {
	srv, _, cleanup := newTestServerWithAudit(t)
	defer cleanup()

	tok := mintTokenWithIss(t, sharedIssuer, "hanzo", "usr_zatsch")
	body, _ := json.Marshal(map[string]any{"value": "created-via-patch", "version": 0, "env": "dev"})
	req, _ := http.NewRequest("PATCH",
		srv.URL+"/v1/kms/orgs/hanzo/secrets/nonexistent/key",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 404 {
		t.Fatalf("PATCH to nonexistent: want 404, got %d", resp.StatusCode)
	}
}

// TestRed3_PostUpsertBumpsVersion — POST upsert always bumps version
// (regardless of caller input) so the version field tracks writes.
func TestRed3_PostUpsertBumpsVersion(t *testing.T) {
	srv, _, cleanup := newTestServerWithAudit(t)
	defer cleanup()

	tok := mintTokenWithIss(t, sharedIssuer, "hanzo", "usr_zatsch")
	for i := 1; i <= 3; i++ {
		body, _ := json.Marshal(map[string]string{
			"path": "seq", "name": "y", "env": "dev", "value": fmt.Sprintf("v%d", i),
		})
		req, _ := http.NewRequest("POST", srv.URL+"/v1/kms/orgs/hanzo/secrets", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 201 {
			t.Fatalf("POST #%d: want 201, got %d", i, resp.StatusCode)
		}
		var r struct{ Version int64 }
		json.NewDecoder(resp.Body).Decode(&r)
		if r.Version != int64(i) {
			t.Fatalf("POST #%d version: want %d, got %d", i, i, r.Version)
		}
	}
}

// TestRed12_ComposeActorID covers the pure unit-level rules:
//   - well-formed sub → "iss:sub"
//   - malformed sub → "unverified:iss:sub"
//   - empty iss/sub → fallback placeholders
func TestRed12_ComposeActorID(t *testing.T) {
	cases := []struct {
		iss, sub string
		want     string
	}{
		{"https://hanzo.id", "usr_abc123", "https://hanzo.id:usr_abc123"},
		{"https://hanzo.id", "svc_alpaca", "https://hanzo.id:svc_alpaca"},
		{"https://hanzo.id", "api_key_01", "https://hanzo.id:api_key_01"},
		{"https://hanzo.id", "admin", "unverified:https://hanzo.id:admin"},
		{"https://hanzo.id", "system", "unverified:https://hanzo.id:system"},
		{"https://hanzo.id", "../etc/passwd", "unverified:https://hanzo.id:../etc/passwd"},
		{"", "usr_abc", "unknown-issuer:usr_abc"},
		{"https://hanzo.id", "", "unverified:https://hanzo.id:anonymous"},
	}
	for _, c := range cases {
		got := composeActorID(c.iss, c.sub)
		if got != c.want {
			t.Errorf("composeActorID(%q,%q) = %q; want %q", c.iss, c.sub, got, c.want)
		}
	}
}

// TestRed12_AuditTrail_CompositeActorID persists a request round-trip
// and then reads the SQLite audit_log directly, asserting the actor_id
// column contains "iss:sub" form.
func TestRed12_AuditTrail_CompositeActorID(t *testing.T) {
	srv, auditPath, cleanup := newTestServerWithAudit(t)
	defer cleanup()

	// Clean IAM token → 201 Created, audit row carries verified iss:sub.
	tok := mintTokenWithIss(t, sharedIssuer, "hanzo", "usr_zatsch")
	body, _ := json.Marshal(map[string]string{
		"path": "audit/test", "name": "k", "env": "dev", "value": "redacted",
	})
	req, _ := http.NewRequest("POST", srv.URL+"/v1/kms/orgs/hanzo/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	http.DefaultClient.Do(req)

	// Rogue-issuer token → 401 Unauthorized at the verification step.
	// Red Part 5 F1: cross-env issuer MUST NOT produce a handler-level
	// success. The handler-level audit stays empty (":anonymous") because
	// authorize() returns zero claims on failure.
	tokBad := mintTokenWithIss(t, "https://rogue.id", "hanzo", "admin")
	req, _ = http.NewRequest("POST", srv.URL+"/v1/kms/orgs/hanzo/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokBad)
	rogueResp, _ := http.DefaultClient.Do(req)
	if rogueResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("rogue iss post-patch must 401, got %d", rogueResp.StatusCode)
	}

	// Drain: flush audit buffer.
	drainAudit(t)

	db, err := sql.Open("sqlite", auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT actor_id, issuer, subject, result FROM audit_log ORDER BY id ASC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actors []string
	var results []int
	for rows.Next() {
		var a, iss, sub string
		var res int
		rows.Scan(&a, &iss, &sub, &res)
		actors = append(actors, a)
		results = append(results, res)
	}
	if len(actors) < 2 {
		t.Fatalf("expected >=2 audit rows, got %d", len(actors))
	}

	// Clean IAM row MUST appear as verified iss:sub. Rogue token row is
	// expected to be a 401 with anonymous actor (no leaking of
	// attacker-controlled iss claim into audit actor_id post-verify).
	foundClean, found401 := false, false
	for i, a := range actors {
		if a == sharedIssuer+":usr_zatsch" && results[i] == http.StatusCreated {
			foundClean = true
		}
		if results[i] == http.StatusUnauthorized {
			found401 = true
		}
	}
	if !foundClean {
		t.Errorf("audit missing clean verified actor_id; got: %v results: %v", actors, results)
	}
	if !found401 {
		t.Errorf("audit missing 401 row for rogue token; got: %v results: %v", actors, results)
	}
}

// TestRed12_AuditActorIDNotJustSub — the smoke test from Red's brief:
// "Decode audit entry, expect actor_id format iss:sub not just sub".
// Fails loudly if any actor_id is a bare subject with no issuer prefix.
func TestRed12_AuditActorIDNotJustSub(t *testing.T) {
	srv, auditPath, cleanup := newTestServerWithAudit(t)
	defer cleanup()

	tok := mintTokenWithIss(t, sharedIssuer, "hanzo", "usr_zatsch")
	for range []int{1, 2, 3} {
		body, _ := json.Marshal(map[string]string{
			"path": "audit/trail", "name": "w", "env": "dev", "value": "x",
		})
		req, _ := http.NewRequest("POST", srv.URL+"/v1/kms/orgs/hanzo/secrets", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		http.DefaultClient.Do(req)
	}
	drainAudit(t)

	db, err := sql.Open("sqlite", auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT actor_id FROM audit_log LIMIT 5`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var a string
		rows.Scan(&a)
		n++
		if !strings.Contains(a, ":") {
			t.Errorf("actor_id %q is bare subject — must be composite iss:sub", a)
		}
		if a == "usr_zatsch" {
			t.Errorf("actor_id must NOT be just the sub; got %q", a)
		}
	}
	if n == 0 {
		t.Fatal("expected at least 1 audit row")
	}
}

// TestRed12_SubPatternRejectsHostile enumerates attacker-supplied sub
// strings and verifies each gets the "unverified:" tag.
func TestRed12_SubPatternRejectsHostile(t *testing.T) {
	hostile := []string{
		"admin",
		"system",
		"root",
		"0",
		"",
		"usr_", // prefix without body
		"usr_../etc/passwd",
		"USR_ABC", // uppercase
		"usr.abc", // dot not allowed
	}
	for _, sub := range hostile {
		got := composeActorID("iam.test", sub)
		if !strings.HasPrefix(got, "unverified:") {
			t.Errorf("hostile sub %q produced clean actor_id %q — must be unverified", sub, got)
		}
	}
}

// drainAudit blocks until every audit entry queued before the call has
// been persisted. Uses the auditor's sentinel-based sync — deterministic,
// no Sleep, no synthetic rows in audit_log.
func drainAudit(t *testing.T) {
	t.Helper()
	globalAuditor.sync()
}
