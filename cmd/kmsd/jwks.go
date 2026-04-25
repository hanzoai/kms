// JWKS cache — per-env RSA public key resolver for JWT verification.
//
// One cache per process. TTL 15min, serialized refresh, fail-closed on
// empty/bad JWKS. Same primitives every Hanzo service uses to verify
// IAM-issued tokens — keep behaviour identical across the platform.
package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwksCacheTTL is how long a fetched JWKS set is trusted. Hanzo IAM
// rotates signing keys on the order of days, so 15 minutes is well below
// the rotation window while cheap enough to not hammer IAM.
const jwksCacheTTL = 15 * time.Minute

type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiry    time.Time
	refreshMu sync.Mutex // serializes refresh to prevent stampede
	url       string
	client    *http.Client
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// resolve returns the RSA public key for the given kid, refreshing the
// cache from the configured JWKS URL when the TTL has expired or the kid
// isn't in the current cache. Returns fail-closed: if JWKS is unreachable
// or empty, returns an error.
func (c *jwksCache) resolve(kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("jwks: JWT missing kid header")
	}

	// Fast path: cache hit and not expired.
	c.mu.RLock()
	if time.Now().Before(c.expiry) {
		if k, ok := c.keys[kid]; ok {
			c.mu.RUnlock()
			return k, nil
		}
	}
	c.mu.RUnlock()

	// Serialize refresh. Only one goroutine fetches; the rest wait and
	// then read the refreshed cache.
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	// Double-check — another goroutine may have just refreshed.
	c.mu.RLock()
	if time.Now().Before(c.expiry) {
		if k, ok := c.keys[kid]; ok {
			c.mu.RUnlock()
			return k, nil
		}
	}
	c.mu.RUnlock()

	if err := c.refresh(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	k, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("jwks: kid %q not found in keyset", kid)
	}
	return k, nil
}

func (c *jwksCache) refresh() error {
	if c.url == "" {
		return errors.New("jwks: KMS_JWKS_URL not configured")
	}
	resp, err := c.client.Get(c.url)
	if err != nil {
		return fmt.Errorf("jwks: GET %s: %w", c.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: %s returned %d", c.url, resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks: decode: %w", err)
	}
	out := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		// use=sig preferred but not mandatory — some IAM builds omit it.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := parseJWKSRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return errors.New("jwks: no usable RSA signing keys")
	}
	c.mu.Lock()
	c.keys = out
	c.expiry = time.Now().Add(jwksCacheTTL)
	c.mu.Unlock()
	return nil
}

func parseJWKSRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
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
		return nil, errors.New("exponent too large")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// resetJWKSCacheForTest is used by jwt_test.go to invalidate the cache
// between test environments so each newJWTTestEnv gets a fresh fetch
// against its own mock JWKS server.
func resetJWKSCacheForTest() {
	if authConfig.jwks != nil {
		authConfig.jwks.mu.Lock()
		authConfig.jwks.keys = nil
		authConfig.jwks.expiry = time.Time{}
		authConfig.jwks.mu.Unlock()
	}
}
