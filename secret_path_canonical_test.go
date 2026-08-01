// Tests that every spelling of a secret path addresses ONE record.
//
// Regression origin: a production secret (chat-index-key/INDEX_MASTER_KEY) was
// written with a leading slash, stored verbatim, and became unreadable by the
// canonical form its kms-operator CR resolves — the CR failed and the value was
// stranded. The write had answered 201. A write that reports success and cannot
// be read back is worse than a failed write: the consumer sees an absent
// secret, not an error, so it degrades to an empty credential.
//
// These assert observable HTTP behaviour end-to-end through the mounted
// handlers, not the shape of an internal call.
package kms

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// postSecretRaw writes a secret and returns the status code (does not fatal),
// so negative cases can assert a rejection.
func postSecretRaw(t *testing.T, srvURL, tok, org, path, name, env, value string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"path": path, "name": name, "env": env, "value": value})
	req, _ := http.NewRequest("POST", srvURL+"/v1/kms/orgs/"+org+"/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s/%s: %v", path, name, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// getSecretRaw reads via the REST path-segment form. pathSeg is inserted into
// the URL verbatim, so a test may pass an already-escaped "%2F..." to exercise
// the encoded-separator spelling.
func getSecretRaw(t *testing.T, srvURL, tok, org, pathSeg, name, env string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", srvURL+"/v1/kms/orgs/"+org+"/secrets/"+pathSeg+"/"+name+"?env="+env, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get %s/%s: %v", pathSeg, name, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return resp.StatusCode, ""
	}
	var out struct {
		Secret struct {
			Value string `json:"value"`
		} `json:"secret"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, string(b))
	}
	return resp.StatusCode, out.Secret.Value
}

// canonicalPath is pure; table-drive the reduction itself.
func TestCanonicalPath(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"datastore", "datastore"},
		{"/datastore", "datastore"},
		{"datastore/", "datastore"},
		{"/datastore/", "datastore"},
		{"/platform/index-chat", "platform/index-chat"},
		{"", ""},
		{"/", ""},
	} {
		if got := canonicalPath(c.in); got != c.want {
			t.Errorf("canonicalPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The exact production failure: written with a leading slash, read canonically.
func TestSecretPath_LeadingSlashWriteIsReadableCanonically(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	if got := postSecretRaw(t, srv.URL, tok, "hanzo", "/platform/index-chat", "INDEX_MASTER_KEY", "default", "V1"); got != 201 {
		t.Fatalf("write with leading slash: want 201, got %d", got)
	}
	status, val := getSecretRaw(t, srv.URL, tok, "hanzo", "platform/index-chat", "INDEX_MASTER_KEY", "default")
	if status != 200 {
		t.Fatalf("canonical read after leading-slash write: want 200, got %d (the stranding bug)", status)
	}
	if val != "V1" {
		t.Fatalf("value mismatch: got %q", val)
	}
}

// Two spellings must not fork into two records: the second write updates the
// first. Before normalizing, "/a/b" and "a/b" were independent keys, so a
// rotation written one way left the other serving the stale value.
func TestSecretPath_SpellingsAddressOneRecord(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	if got := postSecretRaw(t, srv.URL, tok, "hanzo", "/audit/dual", "K", "prod", "OLD"); got != 201 {
		t.Fatalf("first write: %d", got)
	}
	if got := postSecretRaw(t, srv.URL, tok, "hanzo", "audit/dual", "K", "prod", "NEW"); got != 201 {
		t.Fatalf("second write: %d", got)
	}
	// Every spelling must now observe the rotated value.
	for _, spelling := range []string{"audit/dual", "%2Faudit/dual"} {
		status, val := getSecretRaw(t, srv.URL, tok, "hanzo", spelling, "K", "prod")
		if status != 200 {
			t.Fatalf("read %q: want 200, got %d", spelling, status)
		}
		if val != "NEW" {
			t.Errorf("read %q: got %q, want NEW — spellings forked into separate records", spelling, val)
		}
	}
}

// A caller escaping the separator reaches the same record.
func TestSecretPath_EncodedSlashResolvesSameRecord(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	if got := postSecretRaw(t, srv.URL, tok, "hanzo", "audit/enc", "K", "prod", "V"); got != 201 {
		t.Fatalf("write: %d", got)
	}
	status, val := getSecretRaw(t, srv.URL, tok, "hanzo", "%2Faudit/enc", "K", "prod")
	if status != 200 || val != "V" {
		t.Fatalf("encoded-slash read: status=%d val=%q, want 200/V", status, val)
	}
}

// Normalizing must not weaken traversal rejection: stripping the boundary
// slashes still leaves ".." to be caught by safePath.
func TestSecretPath_TraversalStillRejected(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	for _, bad := range []string{"/../etc", "..", "a/../../b", "/a//b"} {
		if got := postSecretRaw(t, srv.URL, tok, "hanzo", bad, "K", "prod", "V"); got != 400 {
			t.Errorf("path %q: want 400, got %d", bad, got)
		}
	}
}
