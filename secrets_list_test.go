// Tests for the metadata-only secret listing endpoint
// GET /v1/kms/orgs/{org}/secrets.
//
// The contract under test, in order of importance:
//  1. No value can ever appear in the response (structural no-leak).
//  2. Authorization is identical to get-one (authorize()+canActOnOrg()) —
//     never weaker. A caller who cannot read the org cannot list it.
//  3. The bare GET does not shadow get-one (Go 1.22 routing precedence).
//  4. prefix/env filters work and are injection-safe (safePath + org
//     confinement).
package kms

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// seedSecret POSTs a secret through the real handler (which also writes the
// version + mtime sibling records). org is the URL org segment; tok must be
// authorized for it.
func seedSecret(t *testing.T, srvURL, tok, org, path, name, env, value string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"path": path, "name": name, "env": env, "value": value})
	req, _ := http.NewRequest("POST", srvURL+"/v1/kms/orgs/"+org+"/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("seed %s/%s: %v", path, name, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("seed %s/%s: want 201, got %d", path, name, resp.StatusCode)
	}
}

// listRaw performs the bare GET list and returns (status, rawBody).
func listRaw(t *testing.T, srvURL, tok, org, query string) (int, string) {
	t.Helper()
	url := srvURL + "/v1/kms/orgs/" + org + "/secrets"
	if query != "" {
		url += "?" + query
	}
	req, _ := http.NewRequest("GET", url, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

type listResponse struct {
	Secrets   []map[string]json.RawMessage `json:"secrets"`
	Count     int                          `json:"count"`
	Truncated bool                         `json:"truncated"`
}

func parseList(t *testing.T, raw string) listResponse {
	t.Helper()
	var lr listResponse
	if err := json.Unmarshal([]byte(raw), &lr); err != nil {
		t.Fatalf("parse list response %q: %v", raw, err)
	}
	return lr
}

// allowedRowKeys is the exact set of keys a metadata row may carry. Anything
// else (especially "value"/"ciphertext") is a leak.
var allowedRowKeys = map[string]bool{
	"path": true, "name": true, "env": true, "version": true, "updatedTime": true,
}

// assertNoValueLeak fails if any value-bearing key or the sentinel value
// appears anywhere in the response.
func assertNoValueLeak(t *testing.T, raw, sentinel string, lr listResponse) {
	t.Helper()
	for _, bad := range []string{`"value"`, `"ciphertext"`, `"wrapped_dek"`, `"secretValue"`, `"secretKey"`, sentinel} {
		if bad != "" && strings.Contains(raw, bad) {
			t.Fatalf("value leak: response contains %q\nbody=%s", bad, raw)
		}
	}
	for i, row := range lr.Secrets {
		for k := range row {
			if !allowedRowKeys[k] {
				t.Fatalf("row %d has disallowed key %q (possible leak)\nbody=%s", i, k, raw)
			}
		}
	}
}

// (a) authorized list returns metadata rows.
func TestList_AuthorizedReturnsMetadata(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	seedSecret(t, srv.URL, tok, "hanzo", "brand/hanzo/plivo", "AUTH_TOKEN", "default", "S1")
	seedSecret(t, srv.URL, tok, "hanzo", "brand/hanzo/stripe", "LIVE_KEY", "default", "S2")

	status, raw := listRaw(t, srv.URL, tok, "hanzo", "")
	if status != 200 {
		t.Fatalf("want 200, got %d: %s", status, raw)
	}
	lr := parseList(t, raw)
	if lr.Count != 2 || len(lr.Secrets) != 2 {
		t.Fatalf("want count 2, got %d: %s", lr.Count, raw)
	}
	// Every row carries the metadata fields; version >= 1; paths are present.
	seenPlivo, seenStripe := false, false
	for _, row := range lr.Secrets {
		var path, name string
		var version int64
		json.Unmarshal(row["path"], &path)
		json.Unmarshal(row["name"], &name)
		if _, ok := row["version"]; !ok {
			t.Fatalf("row missing version: %v", row)
		}
		json.Unmarshal(row["version"], &version)
		if version < 1 {
			t.Fatalf("want version >= 1, got %d", version)
		}
		if path == "brand/hanzo/plivo" && name == "AUTH_TOKEN" {
			seenPlivo = true
		}
		if path == "brand/hanzo/stripe" && name == "LIVE_KEY" {
			seenStripe = true
		}
	}
	if !seenPlivo || !seenStripe {
		t.Fatalf("missing expected rows: plivo=%v stripe=%v\n%s", seenPlivo, seenStripe, raw)
	}
}

// (b) unauthorized: wrong owner → 403; no token → 401. The list must be no
// weaker than get-one.
func TestList_AuthzFailClosed(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	// Seed as hanzo so there IS data to (not) leak.
	hanzoTok := mintToken(t, "hanzo", "user-1")
	seedSecret(t, srv.URL, hanzoTok, "hanzo", "brand/hanzo/plivo", "AUTH_TOKEN", "default", "TOPSECRET")

	// Wrong owner, no role → 403.
	evil := mintToken(t, "evil-org", "attacker")
	status, raw := listRaw(t, srv.URL, evil, "hanzo", "")
	if status != 403 {
		t.Fatalf("wrong-owner list: want 403, got %d: %s", status, raw)
	}
	if strings.Contains(raw, "TOPSECRET") || strings.Contains(raw, "AUTH_TOKEN") {
		t.Fatalf("403 response leaked metadata/value: %s", raw)
	}

	// No token → 401.
	status, _ = listRaw(t, srv.URL, "", "hanzo", "")
	if status != 401 {
		t.Fatalf("no-token list: want 401, got %d", status)
	}

	// Admin (role, different owner) may list via canActOnOrg → 200.
	admin := mintToken(t, "ops", "admin-1", "superadmin")
	status, _ = listRaw(t, srv.URL, admin, "hanzo", "")
	if status != 200 {
		t.Fatalf("admin list: want 200, got %d", status)
	}
}

// (c) response JSON contains NO value field — parse and assert, and the
// sentinel value never appears.
func TestList_NoValueLeak(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	const sentinel = "PLIVO_AUTH_TOKEN_5551234_DO_NOT_LEAK"
	seedSecret(t, srv.URL, tok, "hanzo", "brand/hanzo/plivo", "AUTH_TOKEN", "default", sentinel)

	status, raw := listRaw(t, srv.URL, tok, "hanzo", "")
	if status != 200 {
		t.Fatalf("want 200, got %d: %s", status, raw)
	}
	lr := parseList(t, raw)
	if lr.Count != 1 {
		t.Fatalf("want 1 row, got %d", lr.Count)
	}
	assertNoValueLeak(t, raw, sentinel, lr)
}

// (d) prefix filter works and is injection-safe.
func TestList_PrefixFilterAndInjection(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	seedSecret(t, srv.URL, tok, "hanzo", "brand/hanzo/plivo", "AUTH_TOKEN", "default", "S1")
	seedSecret(t, srv.URL, tok, "hanzo", "brand/hanzo/plivo", "ACCOUNT_SID", "default", "S2")
	seedSecret(t, srv.URL, tok, "hanzo", "brand/hanzo/stripe", "LIVE_KEY", "default", "S3")

	// Narrow to plivo only.
	status, raw := listRaw(t, srv.URL, tok, "hanzo", "prefix=brand/hanzo/plivo/")
	if status != 200 {
		t.Fatalf("prefix list: want 200, got %d: %s", status, raw)
	}
	lr := parseList(t, raw)
	if lr.Count != 2 {
		t.Fatalf("prefix=plivo: want 2 rows, got %d: %s", lr.Count, raw)
	}
	for _, row := range lr.Secrets {
		var path string
		json.Unmarshal(row["path"], &path)
		if !strings.HasPrefix(path, "brand/hanzo/plivo") {
			t.Fatalf("prefix filter bleed: got path %q", path)
		}
	}

	// Injection-safe: traversal, double-slash, null byte → 400; cross-org
	// prefix → 403. None may return 200.
	injection := map[string]int{
		"prefix=brand/hanzo/../lux/": 400, // ".." segment rejected by safePath
		"prefix=brand/hanzo//x/":     400, // "//" rejected by safePath
		"prefix=brand/hanzo/%00":     400, // null byte rejected by safePath
		"prefix=brand/lux/":          403, // valid path but outside org namespace
		"prefix=../../etc/":          400, // traversal
	}
	for q, want := range injection {
		status, raw := listRaw(t, srv.URL, tok, "hanzo", q)
		if status != want {
			t.Fatalf("injection %q: want %d, got %d: %s", q, want, status, raw)
		}
		if status == 200 {
			t.Fatalf("injection %q must not return 200", q)
		}
	}
}

// env filter narrows to one environment.
func TestList_EnvFilter(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	seedSecret(t, srv.URL, tok, "hanzo", "brand/hanzo/plivo", "AUTH_TOKEN", "dev", "D")
	seedSecret(t, srv.URL, tok, "hanzo", "brand/hanzo/plivo", "AUTH_TOKEN", "prod", "P")

	status, raw := listRaw(t, srv.URL, tok, "hanzo", "env=dev")
	if status != 200 {
		t.Fatalf("env list: want 200, got %d", status)
	}
	lr := parseList(t, raw)
	if lr.Count != 1 {
		t.Fatalf("env=dev: want 1 row, got %d: %s", lr.Count, raw)
	}
	var env string
	json.Unmarshal(lr.Secrets[0]["env"], &env)
	if env != "dev" {
		t.Fatalf("env filter: want dev, got %q", env)
	}
}

// (e) empty org → empty list, count 0 (and an empty [], not null).
func TestList_EmptyOrg(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	status, raw := listRaw(t, srv.URL, tok, "hanzo", "")
	if status != 200 {
		t.Fatalf("empty list: want 200, got %d", status)
	}
	lr := parseList(t, raw)
	if lr.Count != 0 || len(lr.Secrets) != 0 {
		t.Fatalf("empty org: want count 0, got %d: %s", lr.Count, raw)
	}
	if !strings.Contains(raw, `"secrets":[]`) {
		t.Fatalf("empty list should serialize secrets as [], got: %s", raw)
	}
}

// (f) the bare GET does not shadow get-one: a real get-one still returns its
// value to an authorized caller, while the bare GET returns the metadata list.
func TestList_RoutingPrecedence_NoShadowGetOne(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	const sentinel = "GET_ONE_STILL_WORKS_42"
	seedSecret(t, srv.URL, tok, "hanzo", "brand/hanzo/plivo", "AUTH_TOKEN", "default", sentinel)

	// get-one: the wildcard route still resolves and returns the value.
	req, _ := http.NewRequest("GET",
		srv.URL+"/v1/kms/orgs/hanzo/secrets/brand/hanzo/plivo/AUTH_TOKEN?env=default", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]map[string]string
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("get-one: want 200, got %d", resp.StatusCode)
	}
	if got["secret"]["value"] != sentinel {
		t.Fatalf("get-one shadowed: want value %q, got %q", sentinel, got["secret"]["value"])
	}

	// bare GET: hits list, returns metadata (no value), count 1.
	status, raw := listRaw(t, srv.URL, tok, "hanzo", "")
	if status != 200 {
		t.Fatalf("bare list: want 200, got %d: %s", status, raw)
	}
	if !strings.Contains(raw, `"count"`) {
		t.Fatalf("bare GET did not hit list handler (no count field): %s", raw)
	}
	lr := parseList(t, raw)
	if lr.Count != 1 {
		t.Fatalf("bare list: want 1 row, got %d", lr.Count)
	}
	assertNoValueLeak(t, raw, sentinel, lr)
}

// updatedTime is populated by the write path (mtime sibling index) and is
// valid RFC3339. Proves the metadata mtime tracking is real, not faked.
func TestList_UpdatedTimeIsRFC3339(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	before := time.Now().Add(-2 * time.Second)
	seedSecret(t, srv.URL, tok, "hanzo", "brand/hanzo/plivo", "AUTH_TOKEN", "default", "S1")

	_, raw := listRaw(t, srv.URL, tok, "hanzo", "")
	lr := parseList(t, raw)
	if lr.Count != 1 {
		t.Fatalf("want 1 row, got %d", lr.Count)
	}
	rawTime, ok := lr.Secrets[0]["updatedTime"]
	if !ok {
		t.Fatalf("updatedTime missing for a freshly written secret: %s", raw)
	}
	var ts string
	json.Unmarshal(rawTime, &ts)
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t.Fatalf("updatedTime %q not RFC3339: %v", ts, err)
	}
	if parsed.Before(before) {
		t.Fatalf("updatedTime %v is before the write started %v", parsed, before)
	}
}

// Admin is confined to the org namespace on the prefix just like everyone
// else: an admin under /orgs/hanzo cannot enumerate brand/lux/ via prefix.
// (Cross-org browse is done by addressing the other org's URL, not by
// escaping the prefix.)
func TestList_PrefixConfinementUniformForAdmin(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	admin := mintToken(t, "ops", "admin-1", "superadmin")

	status, raw := listRaw(t, srv.URL, admin, "hanzo", "prefix=brand/lux/")
	if status != 403 {
		t.Fatalf("admin cross-namespace prefix: want 403, got %d: %s", status, raw)
	}
}
