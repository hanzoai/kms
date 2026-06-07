// Package kmsclient provides a Go client for fetching secrets from the
// Hanzo KMS server. Designed for service-to-service use.
//
// One client, two wire protocols, picked by the Endpoint scheme:
//
//	http://kms.hanzo.svc.cluster.local:8443     → HTTP/JSON (IAM bearer)
//	https://kms.hanzo.ai                        → HTTP/JSON (IAM bearer)
//	zap://kms.hanzo.svc.cluster.local:9999      → ZAP native binary
//	zap+mdns://_kms._tcp                        → ZAP via mDNS discovery
//
// ZAP is the production default for in-cluster service-to-service traffic
// (sub-100µs latency, PQ-hybrid handshake). HTTP is retained for external
// callers, cross-cluster reads, and admin tools.
//
// Auth model differs by transport:
//
//	HTTP: clientId+clientSecret → IAM client_credentials → bearer JWT
//	      verified by kmsd against IAM JWKS. Org scoped via JWT `owner`.
//
//	ZAP:  caller signs every envelope with a mnemonic-derived
//	      *Identity (luxfi/keys.ServiceIdentity). The server verifies
//	      the envelope and asks consensus "is this NodeID authorized
//	      for op on path?". There is no per-pod NodeID string —
//	      identity is derived deterministically from the mnemonic +
//	      service path.
//
// Both transports converge on the same exported API: New, Get, Put,
// Delete, List, GetJSON, FetchEnv.
//
// Example (ZAP, mnemonic-derived identity):
//
//	ident, err := kmsclient.IdentityFromEnv("hanzo/auto")
//	if err != nil { return err }
//	defer ident.Wipe()
//	c, err := kmsclient.New(kmsclient.Config{
//	    Endpoint: "zap://kms.hanzo.svc.cluster.local:9999",
//	    Identity: ident,
//	    Org:      "hanzo",
//	    Env:      "prod",
//	})
//	val, err := c.Get(ctx, "providers/alpaca/dev", "api_key")
package kmsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/luxfi/kms/pkg/zapclient"
)

// Config configures the KMS client.
//
// Pick one transport via Endpoint:
//
//   - http(s)://… — HTTP transport. Requires IAMEndpoint + ClientID +
//     ClientSecret + Org. The Env field is sent as a query param on
//     each call; default "default".
//
//   - zap://host:port — ZAP transport, direct dial. Requires Identity
//     (mnemonic-derived). The kmsd verifies the envelope signature
//     and asks consensus whether the identity's NodeID is authorized
//     for the request's op + path.
//
//   - zap+mdns://… — ZAP transport, mDNS discovery. Same as zap:// minus
//     the explicit address.
//
// IAMEndpoint / ClientID / ClientSecret are accepted on the ZAP path so
// callers can ship the same config struct between transports, but
// they are unused on the wire — the envelope signature is the only gate.
type Config struct {
	// Endpoint is the KMS server URL.
	//
	// http(s)://host:port — HTTP transport (default).
	// zap://host:port — ZAP transport, direct dial.
	// zap+mdns://service — ZAP transport, mDNS discovery (typically
	//   "zap+mdns://_kms._tcp").
	//
	// Required.
	Endpoint string

	// IAMEndpoint is the IAM server URL for client_credentials token
	// exchange. Required on the HTTP path. Ignored on the ZAP path.
	IAMEndpoint string

	// ClientID is the IAM machine-identity client ID. Required on the
	// HTTP path. Ignored on the ZAP path.
	ClientID string

	// ClientSecret is the IAM machine-identity client secret. Required
	// on the HTTP path. Ignored on the ZAP path.
	ClientSecret string

	// Org is the organisation slug (e.g. "hanzo"). Required on every
	// transport; used in URL construction (HTTP) and as the path
	// prefix when a caller does not supply one (ZAP).
	Org string

	// Env is the environment slug the underlying kmsd uses when no
	// explicit env is on the call. Defaults to "default". Honoured on
	// the ZAP path (which has no query string).
	Env string

	// Identity is the mnemonic-derived service identity that signs
	// every ZAP envelope. Required on the ZAP path; the wire fails
	// fast on the first call when nil. The Identity owns its private
	// key; caller is responsible for Wipe() at shutdown.
	//
	// Build it via NewIdentity(mnemonic, servicePath) or
	// IdentityFromEnv(servicePath). Ignored on the HTTP path.
	Identity *Identity

	// TransportNodeID is the ZAP node label used by the transport
	// layer to register itself in the mesh (mDNS / direct-dial peer
	// table). It is NOT the authentication identity — that is
	// Identity (mnemonic-derived). Empty defaults to "kmsclient".
	TransportNodeID string

	// HTTPClient is an optional custom HTTP client. If nil, a default
	// with 15-second timeout is used. Honoured only on the HTTP path.
	HTTPClient *http.Client
}

// Client fetches secrets from KMS. Safe for concurrent use; reuse one
// Client across goroutines so the HTTP token cache or the long-lived
// ZAP connection is shared.
type Client struct {
	// Common fields.
	org      string
	env      string
	endpoint string

	// HTTP fields. Populated when transport == "http".
	iamEndpoint  string
	clientID     string
	clientSecret string
	http         *http.Client

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time

	// ZAP fields. Populated when transport == "zap".
	zap      *zapclient.Client
	zapHost  string // for diagnostics
	identity *Identity

	// transport is "http" or "zap" — set at New() time, immutable.
	transport string
}

// New creates a KMS client. Validation depends on the Endpoint scheme.
//
// HTTP requires Endpoint + IAMEndpoint + ClientID + ClientSecret + Org.
// ZAP requires Endpoint + Org + Identity. The mnemonic-derived
// Identity signs every envelope the server verifies; the consensus
// authorizer then decides on the request.
func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("kmsclient: endpoint is required")
	}
	if cfg.Org == "" {
		return nil, errors.New("kmsclient: org is required")
	}

	env := cfg.Env
	if env == "" {
		env = "default"
	}

	low := strings.ToLower(strings.TrimSpace(cfg.Endpoint))
	switch {
	case strings.HasPrefix(low, "zap://") || strings.HasPrefix(low, "zap+mdns://"):
		return newZAP(cfg, env)
	case strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://"):
		return newHTTP(cfg, env)
	}
	return nil, fmt.Errorf("kmsclient: unsupported endpoint scheme in %q (want http(s):// or zap://)", cfg.Endpoint)
}

// newHTTP validates HTTP-mode config and constructs the Client.
func newHTTP(cfg Config, env string) (*Client, error) {
	if cfg.IAMEndpoint == "" {
		return nil, errors.New("kmsclient: iam endpoint is required (http transport)")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("kmsclient: client id is required (http transport)")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("kmsclient: client secret is required (http transport)")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		transport:    "http",
		endpoint:     strings.TrimRight(cfg.Endpoint, "/"),
		iamEndpoint:  strings.TrimRight(cfg.IAMEndpoint, "/"),
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		org:          cfg.Org,
		env:          env,
		http:         httpClient,
	}, nil
}

// newZAP validates ZAP-mode config and dials the peer.
//
// We dial eagerly so callers see the dial failure at construction time
// rather than on first Get. The connection is reused for every call.
func newZAP(cfg Config, env string) (*Client, error) {
	if cfg.Identity == nil {
		return nil, errors.New("kmsclient: identity is required (zap transport)")
	}
	host, mdns := parseZAPEndpoint(cfg.Endpoint)
	transportNodeID := cfg.TransportNodeID
	if transportNodeID == "" {
		transportNodeID = "kmsclient"
	}
	zcfg := zapclient.Config{
		NodeID:         transportNodeID,
		ServiceType:    "_kms._tcp",
		DefaultPath:    cfg.Org, // unused by GetAt/PutAt below; harmless
		IdentityHeader: cfg.Identity.Header,
		Signer:         cfg.Identity.ServiceIdentity,
	}
	if !mdns {
		zcfg.PeerAddr = host
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	zc, err := zapclient.DialWithConfig(dialCtx, zcfg)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: zap dial %q: %w", cfg.Endpoint, err)
	}
	return &Client{
		transport: "zap",
		endpoint:  cfg.Endpoint,
		org:       cfg.Org,
		env:       env,
		zap:       zc,
		zapHost:   host,
		identity:  cfg.Identity,
	}, nil
}

// parseZAPEndpoint splits "zap://host:port" or "zap+mdns://..." into
// (host, mdns). mdns==true means the caller wants discovery; host is
// empty in that case.
func parseZAPEndpoint(endpoint string) (host string, mdns bool) {
	low := strings.ToLower(strings.TrimSpace(endpoint))
	if strings.HasPrefix(low, "zap+mdns://") {
		return "", true
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return strings.TrimPrefix(strings.TrimPrefix(endpoint, "zap://"), "ZAP://"), false
	}
	return u.Host, false
}

// Close releases any underlying transport handles. Safe to call
// multiple times. Idempotent.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	if c.transport == "zap" && c.zap != nil {
		c.zap.Close()
		c.zap = nil
	}
	return nil
}

// secretPath joins org/path/name into the canonical HTTP URL:
//
//	{endpoint}/v1/kms/orgs/{org}/secrets/{path}/{name}
func (c *Client) secretPath(path, name string) string {
	p := strings.Trim(path, "/")
	n := strings.Trim(name, "/")
	rest := n
	if p != "" {
		rest = p + "/" + n
	}
	segs := strings.Split(rest, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return fmt.Sprintf("%s/v1/kms/orgs/%s/secrets/%s",
		c.endpoint,
		url.PathEscape(c.org),
		strings.Join(segs, "/"),
	)
}

// Get fetches a single secret value by path and name.
//
// On the HTTP path: GET /v1/kms/orgs/{org}/secrets/{path}/{name}.
// On the ZAP path: OpSecretGet (0x0040).
func (c *Client) Get(ctx context.Context, path, name string) (string, error) {
	if c.transport == "zap" {
		return c.zap.GetAt(ctx, path, name, c.env)
	}
	return c.httpGet(ctx, path, name)
}

func (c *Client) httpGet(ctx context.Context, path, name string) (string, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return "", fmt.Errorf("kmsclient: auth: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.secretPath(path, name), nil)
	if err != nil {
		return "", fmt.Errorf("kmsclient: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("kmsclient: secret %s/%s not found", path, name)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kmsclient: status %d: %s", resp.StatusCode, body)
	}
	// Server returns either {"secret":{"value":"..."}} (canonical) or
	// {"value":"..."} (flat). Handle both.
	var wrapped struct {
		Secret struct {
			Value string `json:"value"`
		} `json:"secret"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return "", fmt.Errorf("kmsclient: decode: %w", err)
	}
	if wrapped.Secret.Value != "" {
		return wrapped.Secret.Value, nil
	}
	return wrapped.Value, nil
}

// GetJSON fetches a secret and unmarshals its value as JSON into dst.
func (c *Client) GetJSON(ctx context.Context, path, name string, dst any) error {
	val, err := c.Get(ctx, path, name)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(val), dst); err != nil {
		return fmt.Errorf("kmsclient: unmarshal %s/%s: %w", path, name, err)
	}
	return nil
}

// List returns "path/name" strings for all secrets visible to the
// caller under the given prefix.
//
// On the HTTP path: GET /v1/kms/orgs/{org}/secrets?prefix=…
// On the ZAP path: OpSecretList (0x0042) — names only, no path
// information is surfaced; we prepend the requested prefix so callers
// see identical output across transports.
func (c *Client) List(ctx context.Context, pathPrefix string) ([]string, error) {
	if c.transport == "zap" {
		names, err := c.zap.ListAt(ctx, pathPrefix, c.env)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(names))
		for _, n := range names {
			if pathPrefix != "" {
				out = append(out, pathPrefix+"/"+n)
			} else {
				out = append(out, n)
			}
		}
		return out, nil
	}
	return c.httpList(ctx, pathPrefix)
}

func (c *Client) httpList(ctx context.Context, pathPrefix string) ([]string, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/orgs/%s/secrets",
		c.endpoint,
		url.PathEscape(c.org),
	)
	if pathPrefix != "" {
		u += "?prefix=" + url.QueryEscape(pathPrefix)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kmsclient: status %d: %s", resp.StatusCode, body)
	}
	var wrap struct {
		Items []struct {
			Path string `json:"path"`
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, fmt.Errorf("kmsclient: decode: %w", err)
	}
	out := make([]string, 0, len(wrap.Items))
	for _, it := range wrap.Items {
		if pathPrefix != "" && !strings.HasPrefix(it.Path, pathPrefix) {
			continue
		}
		if it.Path != "" {
			out = append(out, it.Path+"/"+it.Name)
		} else {
			out = append(out, it.Name)
		}
	}
	return out, nil
}

// Put creates or updates a secret.
//
// On the HTTP path: POST /v1/kms/orgs/{org}/secrets (upsert).
// On the ZAP path: OpSecretPut (0x0041).
//
// Requires admin role on the respective auth path.
func (c *Client) Put(ctx context.Context, path, name, value string) error {
	if c.transport == "zap" {
		return c.zap.PutAt(ctx, path, name, c.env, value)
	}
	return c.httpPut(ctx, path, name, value)
}

func (c *Client) httpPut(ctx context.Context, path, name, value string) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/orgs/%s/secrets",
		c.endpoint,
		url.PathEscape(c.org),
	)
	payload, _ := json.Marshal(map[string]string{
		"path":  path,
		"name":  name,
		"value": value,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("kmsclient: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("kmsclient: put status %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

// Delete removes a secret.
//
// On the HTTP path: DELETE /v1/kms/orgs/{org}/secrets/{path}/{name}.
// On the ZAP path: OpSecretDelete (0x0043).
func (c *Client) Delete(ctx context.Context, path, name string) error {
	if c.transport == "zap" {
		return c.zap.DeleteAt(ctx, path, name, c.env)
	}
	return c.httpDelete(ctx, path, name)
}

func (c *Client) httpDelete(ctx context.Context, path, name string) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return fmt.Errorf("kmsclient: auth: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.secretPath(path, name), nil)
	if err != nil {
		return fmt.Errorf("kmsclient: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("kmsclient: secret %s/%s not found", path, name)
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("kmsclient: delete status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// FetchEnv fetches multiple secrets and sets them as environment variables.
// paths is a map of env var name -> "path/name" in KMS.
// Returns the number of secrets successfully fetched.
func (c *Client) FetchEnv(ctx context.Context, paths map[string]string) (int, error) {
	var firstErr error
	count := 0
	for envVar, fullPath := range paths {
		parts := splitPathName(fullPath)
		if parts.path == "" || parts.name == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("kmsclient: invalid path %q for %s", fullPath, envVar)
			}
			continue
		}
		val, err := c.Get(ctx, parts.path, parts.name)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("kmsclient: fetch %s (%s): %w", envVar, fullPath, err)
			}
			continue
		}
		if err := setEnvIfEmpty(envVar, val); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		count++
	}
	return count, firstErr
}

type pathName struct {
	path string
	name string
}

// splitPathName splits "providers/alpaca/dev/api_key" into
// path="providers/alpaca/dev" name="api_key".
func splitPathName(s string) pathName {
	idx := strings.LastIndex(s, "/")
	if idx < 0 {
		return pathName{name: s}
	}
	return pathName{
		path: s[:idx],
		name: s[idx+1:],
	}
}

// setEnvIfEmpty sets an env var only if it is not already set.
// Explicit env vars override KMS values (dev convenience).
func setEnvIfEmpty(key, value string) error {
	if existing, ok := lookupEnv(key); ok && existing != "" {
		return nil
	}
	return setEnv(key, value)
}

// getToken returns a cached IAM access token, refreshing if expired.
// HTTP path only.
func (c *Client) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return c.accessToken, nil
	}

	tokenURL := c.iamEndpoint + "/v1/iam/login/oauth/access_token"
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("iam token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("iam token exchange: status %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("iam token decode: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("iam returned empty access token")
	}

	c.accessToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		c.tokenExpiry = time.Now().Add(1 * time.Hour)
	}

	return c.accessToken, nil
}
