// Shared test utilities. The package-level sharedTestJWT is bound during
// TestMain so every test can produce a signed JWT without re-spinning a
// JWKS server per test.
//
// This replaces the previous mintToken() unsigned-JWT helper. Post-patch
// the KMS authz layer requires real RS256 signatures; an unsigned token
// returns 401 (as Red F3 demands).
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// shared fixtures bound in TestMain.
var (
	sharedPriv     *rsa.PrivateKey
	sharedKid      = "kms-shared-test-kid"
	sharedJWKS     *httptest.Server
	sharedIssuer   = "https://iam.test.satschel.com"
	sharedAudience = "kms"
)

func TestMain(m *testing.M) {
	// Generate a single RSA key for the whole test binary.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("testutil: keygen: " + err.Error())
	}
	sharedPriv = priv

	nB64 := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
	jwksJSON, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{
			{"kty": "RSA", "kid": sharedKid, "use": "sig", "alg": "RS256", "n": nB64, "e": eB64},
		},
	})
	sharedJWKS = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))

	os.Setenv("KMS_EXPECTED_ISSUER", sharedIssuer)
	os.Setenv("KMS_EXPECTED_AUDIENCE", sharedAudience)
	os.Setenv("KMS_JWKS_URL", sharedJWKS.URL)
	os.Setenv("KMS_ENV", "dev")

	applyAuthConfig(loadAuthConfig())
	resetJWKSCacheForTest()

	code := m.Run()
	sharedJWKS.Close()
	os.Exit(code)
}

// mintTestJWTSigned produces an RS256-signed JWT using the shared test
// keypair + kid + JWKS. Defaults iss/aud/exp/iat to the shared test
// fixtures unless the caller overrides them.
func mintTestJWTSigned(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = sharedIssuer
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = sharedAudience
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(10 * time.Minute).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = sharedKid
	s, err := token.SignedString(sharedPriv)
	if err != nil {
		t.Fatalf("mintTestJWTSigned: %v", err)
	}
	return s
}
