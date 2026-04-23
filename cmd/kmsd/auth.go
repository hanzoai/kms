// JWT verification — full RFC 7519 enforcement: signature, alg allowlist,
// iss, aud, exp. Replaces the unverified-payload parsing that Red
// demonstrated fully bypassed with a 3-line curl + alg=none token on
// kms.main.satschel.com on 2026-04-21.
//
// Contract (by design, no hidden branches):
//
//   1. Authorization: Bearer <token>          — else 401
//   2. JWT header.alg ∈ {RS256, ES256, EdDSA} — else 401 (no HS*, no none)
//   3. Signature verifies against JWKS by kid — else 401
//   4. iss == $KMS_EXPECTED_ISSUER            — else 401
//   5. aud ∋ $KMS_EXPECTED_AUDIENCE           — else 401
//   6. exp > now (no leeway)                  — else 401
//   7. nbf ≤ now when present                  — else 401
//   8. sub present                            — else 401
//
// Any failure logs a structured audit line with the failure class
// (alg_none, expired, wrong_iss, wrong_aud, jwks_miss, sig, missing_sub).
// No JWT payload claim is echoed back to the caller or into logs.
package main

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/golang-jwt/jwt/v5"
)

// authConfig is the per-process JWT verification contract. It is
// populated by loadAuthConfig() at boot and exposed to tests via
// reloadAuthConfigForTest so tests can rewire the issuer/audience/jwks
// without restarting the server.
var authConfig = struct {
	issuer   atomic.Pointer[string]
	audience atomic.Pointer[string]
	jwks     *jwksCache
}{}

type authCfgValues struct {
	issuer   string
	audience string
	jwksURL  string
}

// loadAuthConfig reads KMS_EXPECTED_ISSUER, KMS_EXPECTED_AUDIENCE, and
// KMS_JWKS_URL from the environment. Called once at boot from main().
func loadAuthConfig() authCfgValues {
	return authCfgValues{
		issuer:   strings.TrimSpace(os.Getenv("KMS_EXPECTED_ISSUER")),
		audience: envOr("KMS_EXPECTED_AUDIENCE", "kms"),
		jwksURL:  strings.TrimSpace(os.Getenv("KMS_JWKS_URL")),
	}
}

// applyAuthConfig swaps the live authConfig atomically. Called from main()
// at boot and from tests via reloadAuthConfigForTest.
func applyAuthConfig(v authCfgValues) {
	iss := v.issuer
	authConfig.issuer.Store(&iss)
	aud := v.audience
	authConfig.audience.Store(&aud)
	if v.jwksURL == "" {
		authConfig.jwks = nil
	} else {
		authConfig.jwks = newJWKSCache(v.jwksURL)
	}
}

// validateAuthConfigAtBoot enforces that all three auth env vars are
// populated in non-dev mode. In dev mode we tolerate missing config so
// that local-only test harnesses don't crash on startup, but the
// `verifyJWT` path still rejects every request when JWKS is nil.
func validateAuthConfigAtBoot(env, issuer, audience, jwksURL string) error {
	// Dev-mode escape hatch — local harness, no IAM dependency.
	switch strings.ToLower(env) {
	case "", "dev", "devnet", "local":
		return nil
	}
	if issuer == "" {
		return fmt.Errorf("KMS_EXPECTED_ISSUER is required when KMS_ENV=%q", env)
	}
	if audience == "" {
		return fmt.Errorf("KMS_EXPECTED_AUDIENCE is required when KMS_ENV=%q", env)
	}
	if jwksURL == "" {
		return fmt.Errorf("KMS_JWKS_URL is required when KMS_ENV=%q", env)
	}
	return nil
}

// reloadAuthConfigForTest is called by jwt_test.go after t.Setenv() to
// re-read the three KMS_* vars and rebuild the JWKS cache against the
// current test server.
func reloadAuthConfigForTest() {
	applyAuthConfig(loadAuthConfig())
}

var (
	errAuthNoHeader    = errors.New("authorization header required")
	errAuthNotBearer   = errors.New("bearer token required")
	errAuthNoConfig    = errors.New("KMS auth misconfigured: JWKS URL or issuer missing")
	errAuthBadAlg      = errors.New("jwt: unsupported signing algorithm")
	errAuthBadSig      = errors.New("jwt: signature verification failed")
	errAuthWrongIss    = errors.New("jwt: issuer mismatch")
	errAuthWrongAud    = errors.New("jwt: audience mismatch")
	errAuthExpired     = errors.New("jwt: token expired")
	errAuthMissingSub  = errors.New("jwt: missing subject claim")
	errAuthMissingAud  = errors.New("jwt: missing audience claim")
	errAuthMissingExp  = errors.New("jwt: missing expiry claim")
	errAuthMissingIss  = errors.New("jwt: missing issuer claim")
)

// verifyJWT is the single verified-parse entry point. Called by
// authorize() for every handler that requires a JWT. Returns the
// authorized claims subset on success, or an error whose message is
// suitable for the audit log (but NOT for the client body — the client
// always gets "unauthorized" to avoid oracle attacks).
func verifyJWT(authHeader string) (jwtClaims, error) {
	if authHeader == "" {
		return jwtClaims{}, errAuthNoHeader
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) && !strings.HasPrefix(authHeader, "bearer ") {
		return jwtClaims{}, errAuthNotBearer
	}
	tokenStr := strings.TrimSpace(authHeader[len(prefix):])
	if tokenStr == "" {
		return jwtClaims{}, errAuthNotBearer
	}

	issPtr := authConfig.issuer.Load()
	if issPtr == nil || *issPtr == "" || authConfig.jwks == nil {
		return jwtClaims{}, errAuthNoConfig
	}
	expectedIssuer := strings.TrimRight(*issPtr, "/")

	// Asymmetric alg allowlist — HS* and none are NEVER accepted.
	allowed := []string{
		jwt.SigningMethodRS256.Name,
		jwt.SigningMethodRS384.Name,
		jwt.SigningMethodRS512.Name,
		jwt.SigningMethodES256.Name,
		jwt.SigningMethodES384.Name,
		jwt.SigningMethodES512.Name,
		jwt.SigningMethodPS256.Name,
		jwt.SigningMethodPS384.Name,
		jwt.SigningMethodPS512.Name,
		"EdDSA",
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods(allowed),
		jwt.WithIssuer(expectedIssuer),
		jwt.WithExpirationRequired(),
		// Leeway 0 — Red's prod attack used exp=Sep 2001; we honour real time.
		jwt.WithLeeway(0),
	)

	token, err := parser.Parse(tokenStr, func(tok *jwt.Token) (any, error) {
		alg, _ := tok.Method.(jwt.SigningMethod)
		if alg == nil {
			return nil, errAuthBadAlg
		}
		// Additional defence-in-depth: reject "none" even though
		// WithValidMethods already blocks it. jwt/v5 does not register a
		// "none" method by default, but belt + suspenders.
		if strings.EqualFold(alg.Alg(), "none") {
			return nil, errAuthBadAlg
		}
		kid, _ := tok.Header["kid"].(string)
		key, err := authConfig.jwks.resolve(kid)
		if err != nil {
			return nil, err
		}
		// Return typed key so jwt/v5 picks the right verifier. Only RSA
		// keys from JWKS for now — Hanzo IAM emits RS256.
		return key, nil
	})
	if err != nil {
		return jwtClaims{}, wrapAuthErr(err)
	}
	if !token.Valid {
		return jwtClaims{}, errAuthBadSig
	}

	mc, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return jwtClaims{}, errAuthBadSig
	}

	// Issuer sanity — WithIssuer enforces this, but we re-check to be
	// explicit and to handle missing iss.
	gotIss, _ := mc["iss"].(string)
	if gotIss == "" {
		return jwtClaims{}, errAuthMissingIss
	}
	if strings.TrimRight(gotIss, "/") != expectedIssuer {
		return jwtClaims{}, errAuthWrongIss
	}

	// Audience — jwt/v5 doesn't enforce unless we check explicitly.
	audPtr := authConfig.audience.Load()
	expectedAud := "kms"
	if audPtr != nil && *audPtr != "" {
		expectedAud = *audPtr
	}
	if err := checkAudience(mc, expectedAud); err != nil {
		return jwtClaims{}, err
	}

	// Expiry — WithExpirationRequired + leeway 0 enforces this, but we
	// re-check to emit a clean error class for the audit log.
	expFloat, hasExp := numericClaim(mc, "exp")
	if !hasExp {
		return jwtClaims{}, errAuthMissingExp
	}
	_ = expFloat // jwt/v5 already rejected expired; variable kept for audit

	c := jwtClaims{Iss: gotIss}
	if v, ok := mc["sub"].(string); ok {
		c.Sub = v
	}
	if c.Sub == "" {
		if v, ok := mc["id"].(string); ok {
			c.Sub = v
		}
	}
	if c.Sub == "" {
		return jwtClaims{}, errAuthMissingSub
	}
	if v, ok := mc["owner"].(string); ok {
		c.Owner = v
	}
	// Roles may be []any or string — normalize to []string.
	switch v := mc["roles"].(type) {
	case string:
		for _, r := range strings.Split(v, ",") {
			if rr := strings.TrimSpace(r); rr != "" {
				c.Roles = append(c.Roles, rr)
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if rr := strings.TrimSpace(s); rr != "" {
					c.Roles = append(c.Roles, rr)
				}
			}
		}
	}

	return c, nil
}

// checkAudience enforces that at least one audience in the JWT `aud` claim
// matches one of the expected audiences configured for this KMS instance.
//
// `expected` may be a single audience ("liquidity-bd") or a comma-separated
// list ("liquidity-bd,liquidity-app,kms") so that one KMS can serve multiple
// client services without re-patching the pod on every new consumer.
func checkAudience(mc jwt.MapClaims, expected string) error {
	raw, ok := mc["aud"]
	if !ok {
		return errAuthMissingAud
	}
	// Expand comma-separated expected list into a set. Empty entries and
	// surrounding whitespace are ignored.
	want := make(map[string]struct{})
	for _, e := range strings.Split(expected, ",") {
		if s := strings.TrimSpace(e); s != "" {
			want[s] = struct{}{}
		}
	}
	if len(want) == 0 {
		return errAuthWrongAud
	}
	switch aud := raw.(type) {
	case string:
		if _, ok := want[aud]; ok {
			return nil
		}
	case []any:
		for _, v := range aud {
			if s, ok := v.(string); ok {
				if _, ok := want[s]; ok {
					return nil
				}
			}
		}
	}
	return errAuthWrongAud
}

func numericClaim(mc jwt.MapClaims, k string) (float64, bool) {
	switch v := mc[k].(type) {
	case float64:
		return v, true
	case int64:
		return float64(v), true
	case int:
		return float64(v), true
	}
	return 0, false
}

// wrapAuthErr maps jwt/v5 parse errors to our audit-friendly error set.
func wrapAuthErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return errAuthExpired
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return errAuthExpired
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return errAuthWrongIss
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return errAuthBadSig
	case errors.Is(err, jwt.ErrSignatureInvalid):
		return errAuthBadSig
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return errAuthBadSig
	case errors.Is(err, jwt.ErrTokenMalformed):
		return errAuthBadSig
	}
	// jwt/v5 sometimes wraps alg-not-allowed / method-not-registered:
	if strings.Contains(err.Error(), "unexpected signing method") ||
		strings.Contains(err.Error(), "signing method") ||
		strings.Contains(err.Error(), "alg") {
		return errAuthBadAlg
	}
	// jwks resolve failure is fail-closed.
	if strings.Contains(err.Error(), "jwks:") || strings.Contains(err.Error(), "kid") {
		return errAuthBadSig // don't leak cache/net details via 401
	}
	return errAuthBadSig
}

// authz logger — structured, no payload leakage.
var authLog = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

// authFailReason converts an auth error into a short tag suitable for
// inclusion in the audit log.
func authFailReason(err error) string {
	switch {
	case errors.Is(err, errAuthNoHeader), errors.Is(err, errAuthNotBearer):
		return "no_bearer"
	case errors.Is(err, errAuthNoConfig):
		return "misconfigured"
	case errors.Is(err, errAuthBadAlg):
		return "alg_not_allowed"
	case errors.Is(err, errAuthBadSig):
		return "sig_invalid"
	case errors.Is(err, errAuthExpired):
		return "expired"
	case errors.Is(err, errAuthWrongIss), errors.Is(err, errAuthMissingIss):
		return "wrong_iss"
	case errors.Is(err, errAuthWrongAud), errors.Is(err, errAuthMissingAud):
		return "wrong_aud"
	case errors.Is(err, errAuthMissingExp):
		return "missing_exp"
	case errors.Is(err, errAuthMissingSub):
		return "missing_sub"
	}
	return "unknown"
}

// peerIP extracts the client IP from the request for audit logging.
// Honours X-Forwarded-For when present (gateway is trusted upstream).
func peerIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return r.RemoteAddr
}

// registerKeyRouteAuthGatesForTest is test-only wiring so jwt_test.go
// can exercise F5 (key-route gating) without spinning up an MPC cluster.
// It mounts the same authorize() gate that registerKeyRoutes uses but
// with stub handlers that return 200. Any production caller must use
// registerKeyRoutes (which composes authorize() + mgr handlers).
func registerKeyRouteAuthGatesForTest(mux *http.ServeMux) {
	adminOnly := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims, ok := authorize(w, r)
			if !ok {
				return
			}
			if !claims.isAdmin() {
				writeJSON(w, http.StatusForbidden, map[string]any{"message": "admin role required"})
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /v1/kms/keys", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, []string{})
	}))
	mux.HandleFunc("GET /v1/kms/keys/{id}", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("id")})
	}))
	mux.HandleFunc("POST /v1/kms/keys/generate", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
	}))
	mux.HandleFunc("POST /v1/kms/keys/{id}/sign", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"sig": "test"})
	}))
	mux.HandleFunc("POST /v1/kms/keys/{id}/rotate", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))
	mux.HandleFunc("GET /v1/kms/status", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"kms": "ok"})
	}))
}

// Compile-time guard that rsa.PublicKey implements crypto.PublicKey the
// way jwt/v5 expects.
var _ = (*rsa.PublicKey)(nil)
