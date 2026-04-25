// Emergency JWT verification regression — Red Part 5 (2026-04-21).
//
// These tests lock down the exact attacks Red demonstrated on
// kms.hanzo.ai:
//
//	F1 — cross-env JWT acceptance (dev-signed token on main)
//	F2 — expired JWT accepted (exp=Sep 2001)
//	F3 — alg=none / forged signature accepted
//	F4 — audience not validated
//	F7 — owner=="admin" cross-tenant superuser shortcut
//
// Every case MUST return 401 from the KMS HTTP surface. A 200/201/403/404
// is a regression and fails the test.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	badger "github.com/luxfi/zapdb"

	"github.com/luxfi/kms/pkg/store"
)

// jwtTestEnv bundles an RSA key, a mock JWKS server, and an HTTP test server
// wired with the full production handler chain. Every test in this file
// uses one so the attack surface under test is identical to production.
type jwtTestEnv struct {
	priv     *rsa.PrivateKey
	kid      string
	jwks     *httptest.Server
	issuer   string
	audience string
	srv      *httptest.Server
	cleanup  func()
}

func newJWTTestEnv(t *testing.T) *jwtTestEnv {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	kid := "kms-jwt-test-kid"

	nB64 := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
	jwksJSON, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{
			{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": nB64, "e": eB64},
		},
	})
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))

	issuer := "https://iam.test.hanzo.id"
	audience := "kms"

	// Point the KMS authz layer at this JWKS + issuer + audience.
	// t.Setenv restores the previous value when the test ends; we also
	// restore authConfig itself because it is in-memory state and would
	// otherwise keep pointing at a closed JWKS server when later tests run.
	t.Setenv("KMS_EXPECTED_ISSUER", issuer)
	t.Setenv("KMS_EXPECTED_AUDIENCE", audience)
	t.Setenv("KMS_JWKS_URL", jwks.URL)
	// KMS_ENV=dev so boot doesn't refuse missing prod gate — the envs above
	// are still enforced by verifyJWT regardless of KMS_ENV.
	t.Setenv("KMS_ENV", "dev")

	// Reset the module-level JWKS cache between test envs.
	resetJWKSCacheForTest()
	reloadAuthConfigForTest()

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

	return &jwtTestEnv{
		priv:     priv,
		kid:      kid,
		jwks:     jwks,
		issuer:   issuer,
		audience: audience,
		srv:      srv,
		cleanup: func() {
			srv.Close()
			jwks.Close()
			db.Close()
			// t.Setenv will restore env vars; we restore authConfig to the
			// shared TestMain-configured values so subsequent tests see a
			// working JWKS server.
			applyAuthConfig(authCfgValues{
				issuer:   sharedIssuer,
				audience: sharedAudience,
				jwksURL:  sharedJWKS.URL,
			})
			resetJWKSCacheForTest()
		},
	}
}

// mintSigned produces an RS256-signed JWT with the given claims. Every
// happy-path test uses this so we exercise the exact verification path
// production uses.
func (e *jwtTestEnv) mintSigned(claims jwt.MapClaims) string {
	// Default iss / aud / exp / iat unless the caller explicitly sets them.
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = e.issuer
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = e.audience
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(10 * time.Minute).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = e.kid
	s, err := token.SignedString(e.priv)
	if err != nil {
		panic("sign: " + err.Error())
	}
	return s
}

// mintAlgNone builds the exact attack Red used live on prod: header
// `{"alg":"none","typ":"JWT"}`, attacker-chosen payload, empty or garbage
// signature segment.
func mintAlgNone(payload map[string]any, sig string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	pl, _ := json.Marshal(payload)
	body := base64.RawURLEncoding.EncodeToString(pl)
	return header + "." + body + "." + sig
}

// mintHS256Forged builds an HS256-signed JWT using an attacker-chosen
// symmetric secret. Must be rejected because our alg allowlist is
// asymmetric-only (RS256/ES256/EdDSA).
func mintHS256Forged(payload map[string]any, secret string) string {
	claims := jwt.MapClaims(payload)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(secret))
	return s
}

func mustReq(t *testing.T, method, url, bearer string, body []byte) *http.Response {
	t.Helper()
	var r *http.Request
	var err error
	if body != nil {
		r, err = http.NewRequest(method, url, bytes.NewReader(body))
	} else {
		r, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// ── F3 CATASTROPHIC — alg=none must NOT authenticate ──────────────────

func TestJWT_F3_AlgNone_EmptySignature_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	tok := mintAlgNone(map[string]any{
		"iss":   "https://attacker.evil",
		"owner": "admin",
		"sub":   "root",
		"aud":   "kms",
		"exp":   time.Now().Add(time.Hour).Unix(),
	}, "")

	// Write attempt — must be 401, not 201.
	body, _ := json.Marshal(map[string]string{
		"path": "pwn", "name": "k", "env": "dev", "value": "owned",
	})
	resp := mustReq(t, "POST", e.srv.URL+"/v1/kms/orgs/hanzo/secrets", tok, body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F3 alg=none empty-sig POST: want 401, got %d", resp.StatusCode)
	}

	// Read attempt — must be 401.
	resp = mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/pwn/k?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F3 alg=none empty-sig GET: want 401, got %d", resp.StatusCode)
	}

	// Delete attempt — must be 401.
	resp = mustReq(t, "DELETE", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/pwn/k?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F3 alg=none empty-sig DELETE: want 401, got %d", resp.StatusCode)
	}
}

func TestJWT_F3_AlgNone_GarbageSignature_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	tok := mintAlgNone(map[string]any{
		"iss": e.issuer, "owner": "hanzo", "sub": "root",
		"aud": e.audience, "exp": time.Now().Add(time.Hour).Unix(),
	}, "deadbeefdeadbeef")

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F3 alg=none garbage-sig: want 401, got %d", resp.StatusCode)
	}
}

func TestJWT_F3_HS256Forged_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// HS256 with attacker-chosen secret. Must be rejected — our allowlist
	// is asymmetric-only (RS256/ES256/EdDSA). Even if an attacker guesses a
	// weak shared secret there is no shared secret.
	tok := mintHS256Forged(map[string]any{
		"iss": e.issuer, "owner": "hanzo", "sub": "root",
		"aud": e.audience, "exp": time.Now().Add(time.Hour).Unix(),
	}, "forged-shared-secret-xyz")

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F3 HS256 forged: want 401, got %d", resp.StatusCode)
	}
}

// ── F2 CRITICAL — expired JWTs must be rejected ────────────────────────

func TestJWT_F2_Expired_2001_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// exp=1000000000 → 2001-09-09. Red's live-demo value.
	tok := e.mintSigned(jwt.MapClaims{
		"sub":   "user-x",
		"owner": "hanzo",
		"exp":   int64(1000000000),
	})

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F2 exp=2001: want 401, got %d", resp.StatusCode)
	}
}

func TestJWT_F2_ExpiredOneSecondAgo_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	tok := e.mintSigned(jwt.MapClaims{
		"sub":   "user-x",
		"owner": "hanzo",
		"exp":   time.Now().Add(-time.Second).Unix(),
	})

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F2 exp=-1s: want 401, got %d", resp.StatusCode)
	}
}

func TestJWT_F2_MissingExp_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// Sign a token with NO exp claim. RFC 7519 §4.1.4 doesn't require
	// exp, but our contract does — every KMS-bound JWT MUST have one.
	claims := jwt.MapClaims{
		"iss":   e.issuer,
		"aud":   e.audience,
		"sub":   "user-x",
		"owner": "hanzo",
		"iat":   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = e.kid
	tok, _ := token.SignedString(e.priv)

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F2 missing exp: want 401, got %d", resp.StatusCode)
	}
}

// ── F1 CRITICAL — cross-env issuer must be rejected ────────────────────

func TestJWT_F1_DevIssuerOnMain_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// Configure KMS to expect MAIN issuer — but sign a token with DEV issuer.
	t.Setenv("KMS_EXPECTED_ISSUER", "https://iam.hanzo.id")
	reloadAuthConfigForTest()

	tok := e.mintSigned(jwt.MapClaims{
		"iss":   "https://iam.dev.hanzo.id",
		"sub":   "user-x",
		"owner": "hanzo",
		"aud":   "kms",
	})

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F1 dev iss on main: want 401, got %d", resp.StatusCode)
	}
}

func TestJWT_F1_AttackerIssuer_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	tok := e.mintSigned(jwt.MapClaims{
		"iss":   "https://attacker.evil",
		"sub":   "root",
		"owner": "hanzo",
	})

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F1 attacker iss: want 401, got %d", resp.StatusCode)
	}
}

func TestJWT_F1_MissingIss_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// Unsigned-iss token — explicitly omit iss from the payload.
	claims := jwt.MapClaims{
		"aud":   e.audience,
		"sub":   "user-x",
		"owner": "hanzo",
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = e.kid
	tok, _ := token.SignedString(e.priv)

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F1 missing iss: want 401, got %d", resp.StatusCode)
	}
}

// ── F4 HIGH — audience must be validated ────────────────────────────────

func TestJWT_F4_WrongAudience_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	tok := e.mintSigned(jwt.MapClaims{
		"sub":   "user-x",
		"owner": "hanzo",
		"aud":   "ats", // wrong — expected "kms"
	})

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F4 wrong aud: want 401, got %d", resp.StatusCode)
	}
}

func TestJWT_F4_MissingAudience_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// Explicitly omit aud.
	claims := jwt.MapClaims{
		"iss":   e.issuer,
		"sub":   "user-x",
		"owner": "hanzo",
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = e.kid
	tok, _ := token.SignedString(e.priv)

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F4 missing aud: want 401, got %d", resp.StatusCode)
	}
}

// ── F4 — comma-separated expected audience list ────────────────────────

// A comma-separated KMS_EXPECTED_AUDIENCE lets one KMS instance serve
// multiple client services (e.g. BD + app) without re-patching the pod
// on every new consumer. Each service mints its own single-aud token;
// KMS accepts any value that is in the configured list.
func TestJWT_F4_MultiAudience_Accepted(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	t.Setenv("KMS_EXPECTED_AUDIENCE", "hanzo-app, hanzo-app ,kms")
	reloadAuthConfigForTest()

	for _, aud := range []string{"hanzo-app", "hanzo-app", "kms"} {
		tok := e.mintSigned(jwt.MapClaims{
			"sub":   "user-x",
			"owner": "hanzo",
			"aud":   aud,
		})
		resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
		// Not-found or ok — auth passed. The key check is that 401 is not returned.
		if resp.StatusCode == http.StatusUnauthorized {
			t.Fatalf("aud=%q rejected but should be in expected list", aud)
		}
	}

	// Audience outside the list is still rejected.
	tok := e.mintSigned(jwt.MapClaims{
		"sub":   "user-x",
		"owner": "hanzo",
		"aud":   "hanzo-ats",
	})
	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("aud=hanzo-ats: want 401, got %d", resp.StatusCode)
	}
}

// ── F7 CRITICAL — owner=="admin" must NOT grant cross-tenant power ─────

func TestJWT_F7_OwnerAdminCrossTenant_ReadRejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// Seed a secret in org-a via a properly signed org-a token.
	tokA := e.mintSigned(jwt.MapClaims{"sub": "usr-a", "owner": "org-a"})
	body, _ := json.Marshal(map[string]string{
		"path": "shared", "name": "key", "env": "dev", "value": "A-SECRET",
	})
	resp := mustReq(t, "POST", e.srv.URL+"/v1/kms/orgs/org-a/secrets", tokA, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("seed: want 201, got %d", resp.StatusCode)
	}

	// owner=admin MUST NOT bypass tenant scoping (F7). Casdoor client_credentials
	// emits this for every service account — it is NOT a superuser flag.
	tokAdminOwner := e.mintSigned(jwt.MapClaims{
		"sub":   "casdoor-sa",
		"owner": "admin", // Casdoor superuser-app namespace — no longer special
		// no roles claim — must NOT act as superadmin
	})
	resp = mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/org-a/secrets/shared/key?env=dev", tokAdminOwner, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("F7 owner=admin cross-tenant read: want 403, got %d", resp.StatusCode)
	}

}

func TestJWT_F7_OwnerAdminCrossTenant_WriteRejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// owner=admin trying to WRITE org-a secrets without a real role.
	tokAdminOwner := e.mintSigned(jwt.MapClaims{
		"sub":   "casdoor-sa",
		"owner": "admin",
	})
	body, _ := json.Marshal(map[string]string{
		"path": "pwn", "name": "k", "env": "dev", "value": "POISON",
	})
	resp := mustReq(t, "POST", e.srv.URL+"/v1/kms/orgs/org-a/secrets", tokAdminOwner, body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("F7 owner=admin cross-tenant write: want 403, got %d", resp.StatusCode)
	}

	resp = mustReq(t, "DELETE", e.srv.URL+"/v1/kms/orgs/org-a/secrets/pwn/k?env=dev", tokAdminOwner, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("F7 owner=admin cross-tenant delete: want 403, got %d", resp.StatusCode)
	}
}

func TestJWT_F7_SuperadminRoleStillWorks(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// Seed a secret in org-a.
	tokA := e.mintSigned(jwt.MapClaims{"sub": "usr-a", "owner": "org-a"})
	body, _ := json.Marshal(map[string]string{
		"path": "shared", "name": "key", "env": "dev", "value": "A-SECRET",
	})
	resp := mustReq(t, "POST", e.srv.URL+"/v1/kms/orgs/org-a/secrets", tokA, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("seed: want 201, got %d", resp.StatusCode)
	}

	// Explicit superadmin role MUST work — but via roles claim, NOT owner.
	tokSuper := e.mintSigned(jwt.MapClaims{
		"sub":   "ops-admin",
		"owner": "ops",
		"roles": []string{"superadmin"},
	})
	resp = mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/org-a/secrets/shared/key?env=dev", tokSuper, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("superadmin role cross-tenant: want 200, got %d", resp.StatusCode)
	}
}

// ── Happy path — properly signed JWT must accept ───────────────────────

func TestJWT_ValidRS256_Accepted(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	tok := e.mintSigned(jwt.MapClaims{
		"sub":   "user-1",
		"owner": "hanzo",
	})

	body, _ := json.Marshal(map[string]string{
		"path": "providers/alpaca/dev", "name": "api_key",
		"env": "dev", "value": "PK_LIVE",
	})
	resp := mustReq(t, "POST", e.srv.URL+"/v1/kms/orgs/hanzo/secrets", tok, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("valid JWT POST: want 201, got %d", resp.StatusCode)
	}

	resp = mustReq(t, "GET",
		e.srv.URL+"/v1/kms/orgs/hanzo/secrets/providers/alpaca/dev/api_key?env=dev",
		tok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid JWT GET: want 200, got %d", resp.StatusCode)
	}
}

func TestJWT_HappyPathTenantScope_Accepted(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// Owner matches URL org — exactly one way this works.
	tok := e.mintSigned(jwt.MapClaims{"sub": "u", "owner": "org-a"})
	body, _ := json.Marshal(map[string]string{
		"path": "shared", "name": "key", "env": "dev", "value": "A",
	})
	resp := mustReq(t, "POST", e.srv.URL+"/v1/kms/orgs/org-a/secrets", tok, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("tenant-scoped POST: want 201, got %d", resp.StatusCode)
	}
	resp = mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/org-a/secrets/shared/key?env=dev", tok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tenant-scoped GET: want 200, got %d", resp.StatusCode)
	}
}

// ── Signature wrong key — generic RS256 forgery ─────────────────────────

func TestJWT_WrongSigningKey_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	// Sign with a different RSA key — JWKS has the real one.
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := jwt.MapClaims{
		"iss": e.issuer, "aud": e.audience,
		"sub": "u", "owner": "hanzo",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = e.kid
	tok, _ := token.SignedString(wrongKey)

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong signing key: want 401, got %d", resp.StatusCode)
	}
}

func TestJWT_UnknownKid_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	claims := jwt.MapClaims{
		"iss": e.issuer, "aud": e.audience,
		"sub": "u", "owner": "hanzo",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "unknown-kid-zzz" // not in JWKS
	tok, _ := token.SignedString(e.priv)

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown kid: want 401, got %d", resp.StatusCode)
	}
}

func TestJWT_MissingKid_Rejected(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	claims := jwt.MapClaims{
		"iss": e.issuer, "aud": e.audience,
		"sub": "u", "owner": "hanzo",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// explicitly no kid
	tok, _ := token.SignedString(e.priv)

	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", tok, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing kid: want 401, got %d", resp.StatusCode)
	}
}

// ── F5 MEDIUM — registerKeyRoutes must require auth ────────────────────
//
// The key-route handlers are only registered when MPC_VAULT_ID is set, so
// we build a smaller server here with the key routes mounted directly to
// test the gating without spinning up MPC.

func TestJWT_F5_KeyRoutes_RequireAuth(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	dir := filepath.Join(t.TempDir(), "kms-keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := badger.Open(badger.DefaultOptions(dir).WithLogger(nil))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	registerKeyRouteAuthGatesForTest(mux)

	srv := httptest.NewServer(methodAllowlist(stripIdentityHeaders(mux)))
	defer srv.Close()

	// No auth header — must be 401.
	for _, p := range []string{
		"/v1/kms/keys",
		"/v1/kms/keys/abc",
		"/v1/kms/status",
	} {
		resp, _ := http.Get(srv.URL + p)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("F5 %s: want 401, got %d", p, resp.StatusCode)
		}
	}

	// alg=none must be 401 (F3 applies here too).
	evil := mintAlgNone(map[string]any{
		"iss": "https://attacker.evil", "owner": "admin", "sub": "root",
	}, "")
	resp := mustReq(t, "GET", srv.URL+"/v1/kms/keys", evil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F5 keys alg=none: want 401, got %d", resp.StatusCode)
	}

	// POST /v1/kms/keys/generate without auth → 401 (write side).
	genBody, _ := json.Marshal(map[string]any{"validator_id": "v1", "threshold": 2, "parties": 3})
	resp = mustReq(t, "POST", srv.URL+"/v1/kms/keys/generate", "", genBody)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F5 keys/generate no-auth: want 401, got %d", resp.StatusCode)
	}

	// Regular tenant → 403 (needs admin role).
	tenant := e.mintSigned(jwt.MapClaims{"sub": "usr", "owner": "hanzo"})
	resp = mustReq(t, "GET", srv.URL+"/v1/kms/keys", tenant, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("F5 keys tenant-role: want 403, got %d", resp.StatusCode)
	}
}

// ── Error-body contract — failures MUST emit structured JSON ───────────

func TestJWT_ErrorBodyContract(t *testing.T) {
	e := newJWTTestEnv(t)
	defer e.cleanup()

	evil := mintAlgNone(map[string]any{
		"iss": "https://attacker.evil", "owner": "admin", "sub": "root",
	}, "")
	resp := mustReq(t, "GET", e.srv.URL+"/v1/kms/orgs/hanzo/secrets/a/b?env=dev", evil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	msg, _ := body["message"].(string)
	if msg == "" {
		t.Fatalf("error body missing message field: %v", body)
	}
	// Error body must NOT echo the submitted JWT payload fields.
	if strings.Contains(fmt.Sprint(body), "attacker.evil") ||
		strings.Contains(fmt.Sprint(body), "admin") {
		t.Fatalf("error body leaks attacker-controlled claims: %v", body)
	}
}

// ── Startup refuses missing config in prod mode ─────────────────────────

func TestJWT_Startup_RefusesEmptyIssuerInProd(t *testing.T) {
	// We test the validator function directly — the real main() calls
	// log.Fatalf which terminates the test binary, so we isolate the check.
	for _, env := range []string{"prod", "main", "test"} {
		err := validateAuthConfigAtBoot(env, "", "kms", "https://jwks")
		if err == nil {
			t.Errorf("KMS_ENV=%s empty issuer: want error", env)
		}
		err = validateAuthConfigAtBoot(env, "https://iam", "", "https://jwks")
		if err == nil {
			t.Errorf("KMS_ENV=%s empty audience: want error", env)
		}
		err = validateAuthConfigAtBoot(env, "https://iam", "kms", "")
		if err == nil {
			t.Errorf("KMS_ENV=%s empty jwks: want error", env)
		}
		err = validateAuthConfigAtBoot(env, "https://iam", "kms", "https://jwks")
		if err != nil {
			t.Errorf("KMS_ENV=%s full config: unexpected err: %v", env, err)
		}
	}

	// Dev mode: empty is tolerated with a warning.
	if err := validateAuthConfigAtBoot("dev", "", "", ""); err != nil {
		t.Errorf("KMS_ENV=dev empty: want nil, got %v", err)
	}
}
