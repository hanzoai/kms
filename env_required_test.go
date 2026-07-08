// Regression coverage for R-ENV (one-way env). env is a first-class
// component of the storage key (kms/secrets/{path}/{env}/{name}); a
// value-writing mutation that omits env must fail loud (400) instead of
// silently landing in a "default" bucket that project/env/path readers (the
// kms-operator, cluster syncs) never resolve. That split is what let an IAM
// z-password land in env=default while prod kept serving the stale value.
//
// Secret values are never printed — round-trip fidelity is asserted by
// comparing SHA-256 digests.
package kms

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func postSecret(t *testing.T, srvURL, org, tok string, body map[string]string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", srvURL+"/v1/kms/orgs/"+org+"/secrets", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}

func getSecret(t *testing.T, srvURL, org, tok, rest, env string) *http.Response {
	t.Helper()
	u := srvURL + "/v1/kms/orgs/" + org + "/secrets/" + rest
	if env != "" {
		u += "?env=" + env
	}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return resp
}

// A write that omits env must 400 — and must not land anywhere.
func TestEnvRequired_PostWithoutEnv_400(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	resp := postSecret(t, srv.URL, "hanzo", tok, map[string]string{
		"path": "iam-passwords", "name": "Z_PASSWORD", "value": "irrelevant",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("omitted-env write: want 400, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	if msg, _ := m["message"].(string); !strings.Contains(msg, "env is required") {
		t.Fatalf("want env-required message, got %q", msg)
	}

	// Prove the rejected write did not silently populate the default bucket.
	g := getSecret(t, srv.URL, "hanzo", tok, "iam-passwords/Z_PASSWORD", "default")
	defer g.Body.Close()
	if g.StatusCode != http.StatusNotFound {
		t.Fatalf("omitted-env write must not land in env=default: GET want 404, got %d", g.StatusCode)
	}
}

// A write with an explicit env is readable through the exact
// project(org)/env/path resolution the kms-operator uses
// (GET /v1/kms/orgs/{org}/secrets/{path}/{name}?env={env}) — and is NOT
// visible in any other env bucket.
func TestEnvRequired_PostWithEnvProd_ReadableViaProjectEnvPath(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	const secret = "z-password-98f3-do-not-log"
	want := sha256hex(secret)

	resp := postSecret(t, srv.URL, "hanzo", tok, map[string]string{
		"path": "iam-passwords", "name": "Z_PASSWORD", "env": "prod", "value": secret,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("explicit-env write: want 201, got %d", resp.StatusCode)
	}

	// Operator resolution: org=hanzo (project), env=prod, path=/iam-passwords.
	g := getSecret(t, srv.URL, "hanzo", tok, "iam-passwords/Z_PASSWORD", "prod")
	defer g.Body.Close()
	if g.StatusCode != http.StatusOK {
		t.Fatalf("project/env/path read: want 200, got %d", g.StatusCode)
	}
	var got struct {
		Secret struct {
			Value string `json:"value"`
		} `json:"secret"`
	}
	if err := json.NewDecoder(g.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h := sha256hex(got.Secret.Value); h != want {
		t.Fatalf("round-trip value digest mismatch: got %s want %s", h, want)
	}

	// No cross-bucket bleed: env=default must not resolve the prod write.
	gd := getSecret(t, srv.URL, "hanzo", tok, "iam-passwords/Z_PASSWORD", "default")
	defer gd.Body.Close()
	if gd.StatusCode != http.StatusNotFound {
		t.Fatalf("prod write must not be visible in env=default: want 404, got %d", gd.StatusCode)
	}
}

// PATCH (update) is a value-writing mutation too: omitting env in both body
// and query must 400 before any CAS check.
func TestEnvRequired_PatchWithoutEnv_400(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	tok := mintToken(t, "hanzo", "user-1")

	// Seed a prod record so PATCH has a target (env check still precedes CAS).
	seed := postSecret(t, srv.URL, "hanzo", tok, map[string]string{
		"path": "iam-passwords", "name": "Z_PASSWORD", "env": "prod", "value": "v0",
	})
	seed.Body.Close()
	if seed.StatusCode != http.StatusCreated {
		t.Fatalf("seed: want 201, got %d", seed.StatusCode)
	}

	// PATCH with neither body env nor ?env → 400 (before If-Match/version).
	pb, _ := json.Marshal(map[string]any{"value": "rotated", "version": 1})
	req, _ := http.NewRequest("PATCH", srv.URL+"/v1/kms/orgs/hanzo/secrets/iam-passwords/Z_PASSWORD", bytes.NewReader(pb))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("omitted-env PATCH: want 400, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	if msg, _ := m["message"].(string); !strings.Contains(msg, "env is required") {
		t.Fatalf("want env-required message, got %q", msg)
	}
}
