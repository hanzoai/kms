package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"strings"
	"time"
)

// JWKSValidator fetches and caches a JWKS key set from an IAM endpoint.
type JWKSValidator struct {
	url    string
	client *http.Client

	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	ALG string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewJWKSValidator creates a validator that fetches keys from the given JWKS URL.
func NewJWKSValidator(url string) *JWKSValidator {
	return &JWKSValidator{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
		keys:   make(map[string]*rsa.PublicKey),
	}
}

const refreshInterval = 5 * time.Minute

// GetKey returns the RSA public key for the given kid, refreshing the cache if stale.
func (v *JWKSValidator) GetKey(kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	if key, ok := v.keys[kid]; ok && time.Since(v.fetched) < refreshInterval {
		v.mu.RUnlock()
		return key, nil
	}
	v.mu.RUnlock()

	if err := v.refresh(); err != nil {
		return nil, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("auth: unknown kid %q", kid)
	}
	return key, nil
}

func (v *JWKSValidator) refresh() error {
	resp, err := v.client.Get(v.url)
	if err != nil {
		return fmt.Errorf("auth: fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth: jwks returned %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("auth: decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.KTY != "RSA" {
			continue
		}
		pub, err := parseRSAPublicKey(k)
		if err != nil {
			continue
		}
		keys[k.KID] = pub
	}

	if len(keys) == 0 {
		return errors.New("auth: jwks contained no usable RSA keys")
	}

	v.mu.Lock()
	v.keys = keys
	v.fetched = time.Now()
	v.mu.Unlock()
	return nil
}

func parseRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("auth: decode n: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("auth: decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nb)
	e := int(new(big.Int).SetBytes(eb).Int64())

	return &rsa.PublicKey{N: n, E: e}, nil
}

// Issuer derives the issuer URL from the JWKS URL.
// e.g. https://iam.example.com/.well-known/jwks → https://iam.example.com
func (v *JWKSValidator) Issuer() string {
	// Strip the well-known path to get the issuer base.
	u := v.url
	for _, suffix := range []string{"/.well-known/jwks.json", "/.well-known/jwks", "/.well-known/openid-configuration"} {
		u = strings.TrimSuffix(u, suffix)
	}
	return u
}
