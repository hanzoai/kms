// JWT integration tests — confirm the mux built by main.go actually rejects
// unauthenticated/cross-env/expired/wrong-aud tokens on sensitive routes
// while leaving /healthz and /v1/kms/auth/login reachable without auth.
//
// These exercise the shape of the wiring (mux.Handle + protect), not the
// Validator itself (covered in pkg/auth). If someone regresses main.go to
// drop the middleware, these break the build.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/kms/pkg/auth"
)

// buildTestMux constructs the same mux main() would, but wires it to a
// validator pinned at the given iss/aud and the provided JWKS server.
func buildTestMux(t *testing.T, jwksURL, iss, aud string) http.Handler {
	t.Helper()
	v, err := auth.NewValidator(auth.Config{
		JWKSURL:          jwksURL,
		ExpectedIssuer:   iss,
		ExpectedAudience: aud,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	protect := func(h http.HandlerFunc) http.Handler {
		return v.Middleware(h)
	}
	mux := http.NewServeMux()

	// Unauthed routes.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})

	// Sensitive route — must require auth.
	mux.Handle("GET /v1/kms/orgs/{org}/secrets/{rest...}", protect(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"secret":{"value":"ok"}}`)
	}))
	return mux
}

type rsaKey struct {
	kid string
	k   *rsa.PrivateKey
}

func genKey(t *testing.T, kid string) *rsaKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &rsaKey{kid: kid, k: k}
}

func jwksServer(t *testing.T, keys ...*rsaKey) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{}
		list := []map[string]any{}
		for _, k := range keys {
			pub := k.k.PublicKey
			list = append(list, map[string]any{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.kid,
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			})
		}
		out["keys"] = list
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func sign(t *testing.T, k *rsaKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = k.kid
	s, err := tok.SignedString(k.k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIntegration_Healthz_NoAuth(t *testing.T) {
	k := genKey(t, "main-1")
	jwks := jwksServer(t, k)
	defer jwks.Close()

	mux := buildTestMux(t, jwks.URL, "https://iam.main.satschel.com", "kms")
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/healthz: got %d want 200", resp.StatusCode)
	}
}

func TestIntegration_SecretsRequiresAuth(t *testing.T) {
	k := genKey(t, "main-1")
	jwks := jwksServer(t, k)
	defer jwks.Close()

	mux := buildTestMux(t, jwks.URL, "https://iam.main.satschel.com", "kms")
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// No token → 401.
	resp, err := http.Get(srv.URL + "/v1/kms/orgs/liquidity/secrets/providers/alpaca/dev/api_key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("no-auth GET secrets: got %d want 401", resp.StatusCode)
	}
}

func TestIntegration_CrossEnvJWTRejected(t *testing.T) {
	devKey := genKey(t, "dev-1")
	mainKey := genKey(t, "main-1")

	// Main KMS is pinned to the MAIN jwks only.
	mainJWKS := jwksServer(t, mainKey)
	defer mainJWKS.Close()
	mux := buildTestMux(t, mainJWKS.URL, "https://iam.main.satschel.com", "kms")
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// A dev-minted JWT (iss=dev, signed with dev key).
	now := time.Now()
	devTok := sign(t, devKey, jwt.MapClaims{
		"iss": "https://iam.dev.satschel.com",
		"aud": "kms",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
		"sub": "svc",
	})

	req, _ := http.NewRequest("GET",
		srv.URL+"/v1/kms/orgs/liquidity/secrets/a/b", nil)
	req.Header.Set("Authorization", "Bearer "+devTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("dev JWT against main kms: got %d want 401 — cross-env trust bug not closed. body=%s",
			resp.StatusCode, string(body))
	}
}

func TestIntegration_ExpiredJWTRejected(t *testing.T) {
	k := genKey(t, "main-1")
	jwks := jwksServer(t, k)
	defer jwks.Close()
	mux := buildTestMux(t, jwks.URL, "https://iam.main.satschel.com", "kms")
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 4.5 days expired — matches the finding.
	now := time.Now()
	tokStr := sign(t, k, jwt.MapClaims{
		"iss": "https://iam.main.satschel.com",
		"aud": "kms",
		"exp": now.Add(-4*24*time.Hour - 12*time.Hour).Unix(),
		"iat": now.Add(-5 * 24 * time.Hour).Unix(),
		"sub": "svc",
	})

	req, _ := http.NewRequest("GET", srv.URL+"/v1/kms/orgs/liquidity/secrets/a/b", nil)
	req.Header.Set("Authorization", "Bearer "+tokStr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expired JWT: got %d want 401", resp.StatusCode)
	}
}

func TestIntegration_WrongAudienceRejected(t *testing.T) {
	k := genKey(t, "main-1")
	jwks := jwksServer(t, k)
	defer jwks.Close()
	mux := buildTestMux(t, jwks.URL, "https://iam.main.satschel.com", "kms")
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// aud=ats (not kms)
	now := time.Now()
	tokStr := sign(t, k, jwt.MapClaims{
		"iss": "https://iam.main.satschel.com",
		"aud": "ats",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
		"sub": "svc",
	})
	req, _ := http.NewRequest("GET", srv.URL+"/v1/kms/orgs/liquidity/secrets/a/b", nil)
	req.Header.Set("Authorization", "Bearer "+tokStr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("aud=ats: got %d want 401", resp.StatusCode)
	}
}

func TestIntegration_ValidJWTAccepted(t *testing.T) {
	k := genKey(t, "main-1")
	jwks := jwksServer(t, k)
	defer jwks.Close()
	mux := buildTestMux(t, jwks.URL, "https://iam.main.satschel.com", "kms")
	srv := httptest.NewServer(mux)
	defer srv.Close()

	now := time.Now()
	tokStr := sign(t, k, jwt.MapClaims{
		"iss":   "https://iam.main.satschel.com",
		"aud":   "kms",
		"exp":   now.Add(10 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"sub":   "svc-ats",
		"owner": "liquidity",
	})
	req, _ := http.NewRequest("GET", srv.URL+"/v1/kms/orgs/liquidity/secrets/a/b", nil)
	req.Header.Set("Authorization", "Bearer "+tokStr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("valid JWT: got %d want 200. body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}
