// Package auth tests — JWT validation middleware for Hanzo KMS.
//
// These tests exercise the per-env trust boundary: a JWT minted in dev MUST
// NOT be accepted by test or main KMS (and vice versa). Expired tokens MUST
// be rejected with zero clock-skew tolerance by default.
//
// Test matrix:
//   - TestJWT_CrossEnv_Reject        — iss=dev rejected by main validator
//   - TestJWT_Expired_Reject         — 4.5-day-expired token rejected
//   - TestJWT_ExpiredClockSkew_Reject— 30s-expired token rejected (no skew)
//   - TestJWT_WrongAudience_Reject   — aud=ats rejected by kms validator
//   - TestJWT_AlgNone_Reject         — alg=none always rejected
//   - TestJWT_WrongKID_Reject        — kid pointing at unknown key rejected
//   - TestJWT_Valid_Accept           — correctly signed, scoped, fresh JWT accepted
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testKey is a fixed RSA key + kid used across tests. Generating a single key
// once keeps tests deterministic + fast.
type testKey struct {
	kid     string
	private *rsa.PrivateKey
}

func newTestKey(t *testing.T, kid string) *testKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &testKey{kid: kid, private: priv}
}

// jwksHandler returns an HTTP handler that serves the given keys as a JWKS
// document. Each key is keyed by its kid.
func jwksHandler(keys ...*testKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{"keys": []map[string]any{}}
		list := out["keys"].([]map[string]any)
		for _, k := range keys {
			pub := k.private.PublicKey
			list = append(list, map[string]any{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": k.kid,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			})
		}
		out["keys"] = list
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// mintJWT signs a token with the given key + kid. claims overrides defaults.
func mintJWT(t *testing.T, k *testKey, alg jwt.SigningMethod, claims jwt.MapClaims, kidOverride string) string {
	t.Helper()
	tok := jwt.NewWithClaims(alg, claims)
	if kidOverride != "" {
		tok.Header["kid"] = kidOverride
	} else {
		tok.Header["kid"] = k.kid
	}
	s, err := tok.SignedString(k.private)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return s
}

// defaultClaims returns a minimal valid claim set an env can override.
func defaultClaims(iss, aud string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"sub": "svc-ats",
		"owner": "liquidity",
	}
}

// makeValidator spins up a JWKS HTTP server + configures a Validator pinned
// to that JWKS URL + the given expected iss/aud. Returns the validator and a
// cleanup function.
func makeValidator(t *testing.T, keys []*testKey, expectedIss, expectedAud string) (*Validator, func()) {
	t.Helper()
	srv := httptest.NewServer(jwksHandler(keys...))
	v, err := NewValidator(Config{
		JWKSURL:          srv.URL,
		ExpectedIssuer:   expectedIss,
		ExpectedAudience: expectedAud,
		// Leeway intentionally 0 for KMS.
	})
	if err != nil {
		srv.Close()
		t.Fatalf("NewValidator: %v", err)
	}
	return v, srv.Close
}

// ------------------------------------------------------------------
// TestJWT_CrossEnv_Reject — dev-signed JWT cannot authenticate to main.
// ------------------------------------------------------------------
func TestJWT_CrossEnv_Reject(t *testing.T) {
	// Each env has its OWN JWKS + its OWN signing key.
	devKey := newTestKey(t, "dev-key-1")
	mainKey := newTestKey(t, "main-key-1")

	// Set up a main validator (pinned to main's JWKS only, main's iss only).
	v, stop := makeValidator(t, []*testKey{mainKey},
		"https://iam.main.satschel.com", "kms")
	defer stop()

	// Mint a token signed by dev's key with dev's iss.
	devToken := mintJWT(t, devKey, jwt.SigningMethodRS256,
		defaultClaims("https://iam.dev.satschel.com", "kms"), "")

	_, err := v.ValidateToken(devToken)
	if err == nil {
		t.Fatalf("dev JWT was accepted by main validator — cross-env trust bug")
	}
	// Two possible rejection paths depending on order of checks:
	//  1. KID miss: main JWKS doesn't know dev-key-1
	//  2. iss mismatch: if main validator fetched dev's JWKS somehow
	// Either is a valid rejection. We assert at least one is reported.
	t.Logf("cross-env rejected (as expected): %v", err)
}

// ------------------------------------------------------------------
// TestJWT_Expired_Reject — 4.5-day-expired JWT is rejected.
// ------------------------------------------------------------------
func TestJWT_Expired_Reject(t *testing.T) {
	k := newTestKey(t, "main-key-1")
	v, stop := makeValidator(t, []*testKey{k},
		"https://iam.main.satschel.com", "kms")
	defer stop()

	claims := defaultClaims("https://iam.main.satschel.com", "kms")
	now := time.Now()
	// 4.5 days ago — matches the finding from sandbox-KMS agent.
	claims["exp"] = now.Add(-4*24*time.Hour - 12*time.Hour).Unix()
	claims["iat"] = now.Add(-5 * 24 * time.Hour).Unix()
	claims["nbf"] = now.Add(-5 * 24 * time.Hour).Unix()

	tokStr := mintJWT(t, k, jwt.SigningMethodRS256, claims, "")

	_, err := v.ValidateToken(tokStr)
	if err == nil {
		t.Fatalf("4.5-day-expired JWT was accepted — exp not enforced")
	}
	if !errorContains(err, "expired") && !errorContains(err, "exp") {
		t.Fatalf("expired JWT rejected but not with exp error: %v", err)
	}
}

// ------------------------------------------------------------------
// TestJWT_ExpiredClockSkew_Reject — even 30s expired must be rejected.
// KMS auth requires zero clock-skew tolerance — short-lived tokens are
// already ephemeral; sloppy clocks are an ops bug, not an auth policy.
// ------------------------------------------------------------------
func TestJWT_ExpiredClockSkew_Reject(t *testing.T) {
	k := newTestKey(t, "main-key-1")
	v, stop := makeValidator(t, []*testKey{k},
		"https://iam.main.satschel.com", "kms")
	defer stop()

	claims := defaultClaims("https://iam.main.satschel.com", "kms")
	claims["exp"] = time.Now().Add(-30 * time.Second).Unix()

	tokStr := mintJWT(t, k, jwt.SigningMethodRS256, claims, "")

	_, err := v.ValidateToken(tokStr)
	if err == nil {
		t.Fatalf("30s-expired JWT accepted — clock skew tolerance should be 0")
	}
}

// ------------------------------------------------------------------
// TestJWT_WrongAudience_Reject — aud=ats cannot access KMS.
// ------------------------------------------------------------------
func TestJWT_WrongAudience_Reject(t *testing.T) {
	k := newTestKey(t, "main-key-1")
	v, stop := makeValidator(t, []*testKey{k},
		"https://iam.main.satschel.com", "kms")
	defer stop()

	// Token legitimate for ATS but presented to KMS.
	claims := defaultClaims("https://iam.main.satschel.com", "ats")
	tokStr := mintJWT(t, k, jwt.SigningMethodRS256, claims, "")

	_, err := v.ValidateToken(tokStr)
	if err == nil {
		t.Fatalf("aud=ats JWT was accepted by kms validator")
	}
	if !errorContains(err, "audience") && !errorContains(err, "aud") {
		t.Fatalf("wrong-aud JWT rejected but not with audience error: %v", err)
	}
}

// ------------------------------------------------------------------
// TestJWT_AlgNone_Reject — unsigned JWT is always rejected.
// ------------------------------------------------------------------
func TestJWT_AlgNone_Reject(t *testing.T) {
	k := newTestKey(t, "main-key-1")
	v, stop := makeValidator(t, []*testKey{k},
		"https://iam.main.satschel.com", "kms")
	defer stop()

	// Build an alg=none token manually — golang-jwt refuses to sign alg=none
	// but the parser will still get passed a forged blob.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"main-key-1"}`))
	claimsBlob, _ := json.Marshal(defaultClaims("https://iam.main.satschel.com", "kms"))
	body := base64.RawURLEncoding.EncodeToString(claimsBlob)
	noneTok := fmt.Sprintf("%s.%s.", header, body)

	_, err := v.ValidateToken(noneTok)
	if err == nil {
		t.Fatalf("alg=none JWT was accepted — algorithm confusion attack succeeded")
	}
}

// ------------------------------------------------------------------
// TestJWT_WrongKID_Reject — kid pointing at unknown key is rejected.
// ------------------------------------------------------------------
func TestJWT_WrongKID_Reject(t *testing.T) {
	legit := newTestKey(t, "main-key-1")
	attacker := newTestKey(t, "main-key-2") // attacker key, NOT in JWKS

	// Validator only knows about legit (kid=main-key-1).
	v, stop := makeValidator(t, []*testKey{legit},
		"https://iam.main.satschel.com", "kms")
	defer stop()

	// Attacker signs with their key but sets kid=main-key-1 (kid shadowing).
	claims := defaultClaims("https://iam.main.satschel.com", "kms")
	tokStr := mintJWT(t, attacker, jwt.SigningMethodRS256, claims, "main-key-1")

	_, err := v.ValidateToken(tokStr)
	if err == nil {
		t.Fatalf("attacker JWT with shadow kid was accepted — kid not resolved against JWKS")
	}
}

// ------------------------------------------------------------------
// TestJWT_Valid_Accept — sanity: legitimate JWT passes.
// ------------------------------------------------------------------
func TestJWT_Valid_Accept(t *testing.T) {
	k := newTestKey(t, "main-key-1")
	v, stop := makeValidator(t, []*testKey{k},
		"https://iam.main.satschel.com", "kms")
	defer stop()

	tokStr := mintJWT(t, k, jwt.SigningMethodRS256,
		defaultClaims("https://iam.main.satschel.com", "kms"), "")

	claims, err := v.ValidateToken(tokStr)
	if err != nil {
		t.Fatalf("valid JWT rejected: %v", err)
	}
	if claims["owner"] != "liquidity" {
		t.Fatalf("owner claim not propagated: %v", claims)
	}
}

// errorContains returns true if the error chain contains the given
// case-insensitive substring. Safe when err is nil.
func errorContains(err error, substr string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(msg); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			a := msg[i+j]
			b := substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
