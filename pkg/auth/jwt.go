// Package auth enforces JWT validation for Hanzo KMS.
//
// One env = one JWKS = one issuer = one audience. No cross-env trust,
// no shared keyrings, no alg=none, no clock skew. JWTs that do not
// exactly match the env's expected issuer + audience + kid registered
// in the env's JWKS are rejected.
//
// Wire-up:
//
//	v, err := auth.NewValidator(auth.Config{
//	    JWKSURL:          "https://iam.main.satschel.com/.well-known/jwks.json",
//	    ExpectedIssuer:   "https://iam.main.satschel.com",
//	    ExpectedAudience: "kms",
//	})
//	if err != nil { log.Fatal(err) }
//	mux.Handle("POST /v1/kms/orgs/{org}/secrets", v.Middleware(handler))
//
// Health endpoints (/healthz, /readyz) are intentionally exempted from
// JWT — caller is responsible for not wrapping them.
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config wires a Validator with per-env trust boundary.
//
// ExpectedIssuer + ExpectedAudience are REQUIRED. A zero Config is
// intentionally not valid — the calling service MUST declare which
// env it is defending so cross-env trust is impossible by construction.
type Config struct {
	// JWKSURL is the env-specific JWKS endpoint. One URL per env.
	JWKSURL string

	// ExpectedIssuer is the iss claim value required on every token.
	// Must match the env's IAM iss exactly — no prefix matching, no
	// suffix stripping, no list. One issuer per env.
	ExpectedIssuer string

	// ExpectedAudience is the aud claim value required on every token.
	// For KMS this is "kms". For other services, pass that service's
	// audience. Tokens with aud=ats cannot hit kms and vice versa.
	ExpectedAudience string

	// Leeway is clock skew tolerance. Defaults to 0 (none). Max 5s —
	// KMS auth does not need skew tolerance since short-lived tokens
	// are already ephemeral.
	Leeway time.Duration

	// Clock optionally overrides time.Now for deterministic tests.
	// Zero value = real clock.
	Clock func() time.Time

	// RefreshInterval is how often to re-fetch the JWKS. Defaults to 5m.
	// Keys are cached between refreshes.
	RefreshInterval time.Duration

	// HTTPClient is used to fetch the JWKS. Defaults to a client with a
	// 10s timeout. Tests inject httptest.Server URLs via JWKSURL and use
	// the default client.
	HTTPClient *http.Client
}

// Validator validates JWTs against a single env's JWKS, issuer, and audience.
type Validator struct {
	cfg    Config
	parser *jwt.Parser
	client *http.Client

	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey // kid -> pubkey
	fetched time.Time
}

// Errors returned by ValidateToken. All are leaf errors with no inner detail
// leaked to clients — this prevents oracle attacks.
var (
	ErrMissingToken    = errors.New("auth: missing token")
	ErrInvalidToken    = errors.New("auth: invalid token")
	ErrExpiredToken    = errors.New("auth: token expired")
	ErrInvalidIssuer   = errors.New("auth: invalid issuer")
	ErrInvalidAudience = errors.New("auth: invalid audience")
	ErrUnknownKID      = errors.New("auth: unknown kid")
	ErrAlgNotAllowed   = errors.New("auth: algorithm not allowed")
	ErrJWKSUnavailable = errors.New("auth: jwks unavailable")
)

// maxLeeway caps how lax a KMS operator can configure the validator.
// 5 seconds is plenty for NTP-synced clocks; anything more is a smell.
const maxLeeway = 5 * time.Second

// NewValidator constructs a Validator, fetches the JWKS once, and returns
// an error if the initial fetch fails. Subsequent refreshes happen lazily
// when a kid misses — a broken JWKS endpoint should not brick the validator
// once it has some keys cached.
//
// Fails fast if required config is missing — KMS must not start with a
// misconfigured trust boundary.
func NewValidator(cfg Config) (*Validator, error) {
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("auth: JWKSURL required")
	}
	if cfg.ExpectedIssuer == "" {
		return nil, fmt.Errorf("auth: ExpectedIssuer required")
	}
	if cfg.ExpectedAudience == "" {
		return nil, fmt.Errorf("auth: ExpectedAudience required")
	}
	if cfg.Leeway < 0 || cfg.Leeway > maxLeeway {
		return nil, fmt.Errorf("auth: Leeway out of range [0, %s]", maxLeeway)
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}

	parser := jwt.NewParser(
		// WithValidMethods constrains the acceptable alg set. alg=none is
		// NOT in the list → rejected. HS256 is NOT in the list → no symmetric
		// key confusion with a leaked JWKS n=<public modulus>.
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		// WithExpirationRequired forces every token to carry exp.
		jwt.WithExpirationRequired(),
		// WithIssuer enforces an exact iss match.
		jwt.WithIssuer(cfg.ExpectedIssuer),
		// WithAudience enforces aud contains ExpectedAudience.
		jwt.WithAudience(cfg.ExpectedAudience),
		// WithLeeway caps at 5s; typically 0 for KMS.
		jwt.WithLeeway(cfg.Leeway),
		// WithIssuedAt rejects tokens issued in the future.
		jwt.WithIssuedAt(),
		// Inject the clock for deterministic tests.
		jwt.WithTimeFunc(cfg.Clock),
	)

	v := &Validator{
		cfg:    cfg,
		parser: parser,
		client: cfg.HTTPClient,
		keys:   map[string]*rsa.PublicKey{},
	}
	if err := v.refresh(); err != nil {
		return nil, err
	}
	return v, nil
}

// ValidateToken parses tokenStr, validates all standard claims + our pinned
// iss/aud, looks the kid up in the env-specific JWKS, and verifies the
// signature. Returns the parsed claims on success.
func (v *Validator) ValidateToken(tokenStr string) (jwt.MapClaims, error) {
	if tokenStr == "" {
		return nil, ErrMissingToken
	}

	claims := jwt.MapClaims{}
	tok, err := v.parser.ParseWithClaims(tokenStr, claims, v.keyFunc)
	if err != nil {
		return nil, mapJWTError(err)
	}
	if !tok.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// keyFunc resolves the signing key from the JWKS using the kid header.
// Missing/empty kid → reject (no default key).
func (v *Validator) keyFunc(tok *jwt.Token) (any, error) {
	kid, _ := tok.Header["kid"].(string)
	if kid == "" {
		return nil, ErrUnknownKID
	}
	v.mu.RLock()
	key, ok := v.keys[kid]
	fetched := v.fetched
	v.mu.RUnlock()

	if ok {
		return key, nil
	}

	// Lazy refresh on miss — but rate-limit to avoid abuse. If the last
	// fetch was within the refresh interval, don't hammer the IAM JWKS.
	if v.cfg.Clock().Sub(fetched) < v.cfg.RefreshInterval {
		return nil, ErrUnknownKID
	}
	if err := v.refresh(); err != nil {
		return nil, ErrJWKSUnavailable
	}

	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok = v.keys[kid]
	if !ok {
		return nil, ErrUnknownKID
	}
	return key, nil
}

// refresh fetches the JWKS from the configured URL and replaces the cache.
// Caller must not hold the lock. Returns an error only on total failure —
// partial failures (one malformed key) are logged and skipped.
func (v *Validator) refresh() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("auth: build jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth: jwks status %d", resp.StatusCode)
	}

	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("auth: decode jwks: %w", err)
	}

	next := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		// Reject unsafe alg advertisements — the validator's ValidMethods
		// already enforce this at parse time, but we also skip caching a
		// key that claims alg=none/HS256.
		if k.Alg != "" && !isAllowedAlg(k.Alg) {
			continue
		}
		pub, err := jwkToRSA(k.N, k.E)
		if err != nil {
			continue
		}
		next[k.Kid] = pub
	}
	if len(next) == 0 {
		return fmt.Errorf("auth: jwks contained no usable keys")
	}

	v.mu.Lock()
	v.keys = next
	v.fetched = v.cfg.Clock()
	v.mu.Unlock()
	return nil
}

// Middleware returns an http.Handler wrapper that validates Bearer tokens
// and injects the claims into the request context via ContextKey.
//
// On any failure, responds 401 with a minimal JSON body — no error detail,
// no token echo, no timing oracle on the detail string.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := extractBearer(r)
		if tok == "" {
			writeUnauthorized(w, "missing token")
			return
		}
		claims, err := v.ValidateToken(tok)
		if err != nil {
			writeUnauthorized(w, "invalid token")
			return
		}
		ctx := context.WithValue(r.Context(), ContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ContextKey keys the claims in the request context. Unexported alias type
// prevents collisions.
type ContextKey struct{}

// ClaimsFromContext returns the claims stored in the context, or nil.
func ClaimsFromContext(ctx context.Context) jwt.MapClaims {
	c, _ := ctx.Value(ContextKey{}).(jwt.MapClaims)
	return c
}

// ------ helpers ------

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func writeUnauthorized(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"statusCode": 401,
		"message":    "unauthorized",
		"reason":     reason,
	})
}

func isAllowedAlg(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
		return true
	}
	return false
}

// jwkToRSA parses a JWK {n,e} pair (base64url, no padding) into an rsa.PublicKey.
func jwkToRSA(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("exponent too large")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// mapJWTError normalizes golang-jwt errors to our sentinel set. The detail
// strings from jwt/v5 are stable but we flatten them to predictable labels
// for test assertions + audit logs.
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("%w: %v", ErrExpiredToken, err)
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return fmt.Errorf("%w: %v", ErrInvalidIssuer, err)
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return fmt.Errorf("%w: %v", ErrInvalidAudience, err)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid),
		errors.Is(err, jwt.ErrTokenUnverifiable):
		return fmt.Errorf("%w: signature", ErrInvalidToken)
	case errors.Is(err, jwt.ErrTokenMalformed):
		return fmt.Errorf("%w: malformed", ErrInvalidToken)
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return fmt.Errorf("%w: nbf", ErrInvalidToken)
	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return fmt.Errorf("%w: iat", ErrInvalidToken)
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return fmt.Errorf("%w: missing claim", ErrInvalidToken)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return fmt.Errorf("%w: signature", ErrInvalidToken)
	}
	// Unknown error: map to generic invalid token. Include nested detail
	// so tests can assert substring matches but production should log-only.
	return fmt.Errorf("%w: %v", ErrInvalidToken, err)
}
