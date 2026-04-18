// Package kmsclient provides a Go client for fetching secrets from the Hanzo KMS
// server. Designed for service-to-service use: authenticate via IAM client_credentials
// grant, then fetch secrets by path/name.
//
// Usage:
//
//	c, err := kmsclient.New(kmsclient.Config{
//	    Endpoint:     "http://kms.liquidity.svc.cluster.local:8443",
//	    IAMEndpoint:  "http://iam.liquidity.svc.cluster.local:8000",
//	    ClientID:     os.Getenv("IAM_CLIENT_ID"),
//	    ClientSecret: os.Getenv("IAM_CLIENT_SECRET"),
//	    Org:          "liquidity",
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
)

// Config configures the KMS client.
type Config struct {
	// Endpoint is the KMS server URL (e.g. "http://kms.liquidity.svc.cluster.local:8443").
	Endpoint string

	// IAMEndpoint is the IAM server URL for token exchange
	// (e.g. "http://iam.liquidity.svc.cluster.local:8000").
	IAMEndpoint string

	// ClientID is the IAM service account client ID.
	ClientID string

	// ClientSecret is the IAM service account client secret.
	ClientSecret string

	// Org is the organization slug (e.g. "liquidity").
	Org string

	// HTTPClient is an optional custom HTTP client. If nil, a default with
	// 15-second timeout is used.
	HTTPClient *http.Client
}

// Client fetches secrets from the KMS server using IAM service account auth.
type Client struct {
	endpoint     string
	iamEndpoint  string
	clientID     string
	clientSecret string
	org          string
	http         *http.Client

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

// New creates a KMS client. Returns an error if required fields are missing.
func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("kmsclient: endpoint is required")
	}
	if cfg.IAMEndpoint == "" {
		return nil, errors.New("kmsclient: iam endpoint is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("kmsclient: client id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("kmsclient: client secret is required")
	}
	if cfg.Org == "" {
		return nil, errors.New("kmsclient: org is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	return &Client{
		endpoint:     strings.TrimRight(cfg.Endpoint, "/"),
		iamEndpoint:  strings.TrimRight(cfg.IAMEndpoint, "/"),
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		org:          cfg.Org,
		http:         httpClient,
	}, nil
}

// resolveSecretID looks up a secret by (org, path, name) and returns its canonical id.
// Uses the one canonical path: /v1/kms/tenants/{tenantId}/secrets?path=&name=.
func (c *Client) resolveSecretID(ctx context.Context, path, name string) (string, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return "", fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/tenants/%s/secrets?path=%s&name=%s",
		c.endpoint,
		url.PathEscape(c.org),
		url.QueryEscape(path),
		url.QueryEscape(name),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kmsclient: status %d: %s", resp.StatusCode, body)
	}
	var wrap struct {
		Items []struct {
			SecretID string `json:"secretId"`
			Path     string `json:"path"`
			Name     string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return "", fmt.Errorf("kmsclient: decode: %w", err)
	}
	for _, it := range wrap.Items {
		if it.Path == path && it.Name == name && it.SecretID != "" {
			return it.SecretID, nil
		}
	}
	return "", fmt.Errorf("kmsclient: secret %s/%s not found", path, name)
}

// Get fetches a single secret value by path and name.
// Resolves (path, name) to the canonical secretId, then reads via
// /v1/kms/secrets/{secretId} — the one canonical read path.
func (c *Client) Get(ctx context.Context, path, name string) (string, error) {
	id, err := c.resolveSecretID(ctx, path, name)
	if err != nil {
		return "", err
	}
	return c.GetByID(ctx, id)
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

// List returns "path/name" strings for all secrets visible to the caller.
// Uses the canonical tenant listing at /v1/kms/tenants/{tenantId}/secrets.
func (c *Client) List(ctx context.Context, pathPrefix string) ([]string, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/tenants/%s/secrets",
		c.endpoint,
		url.PathEscape(c.org),
	)
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
		out = append(out, it.Path+"/"+it.Name)
	}
	return out, nil
}

// Put creates or updates a secret via the canonical
// POST /v1/kms/tenants/{tenantId}/secrets route (on create) or
// PATCH /v1/kms/secrets/{secretId} (on update). Requires secret-admin role.
func (c *Client) Put(ctx context.Context, path, name, value string) error {
	if id, err := c.resolveSecretID(ctx, path, name); err == nil {
		_, err := c.UpdateSecret(ctx, id, value, nil)
		return err
	}
	token, err := c.getToken(ctx)
	if err != nil {
		return fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/tenants/%s/secrets",
		c.endpoint,
		url.PathEscape(c.org),
	)
	payload, _ := json.Marshal(map[string]string{"path": path, "name": name, "value": value})
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

// Delete removes a secret by (path, name). Routes through DELETE /v1/kms/secrets/{secretId}.
func (c *Client) Delete(ctx context.Context, path, name string) error {
	id, err := c.resolveSecretID(ctx, path, name)
	if err != nil {
		return err
	}
	return c.DeleteByID(ctx, id)
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

// splitPathName splits "providers/alpaca/dev/api_key" into path="providers/alpaca/dev" name="api_key".
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
// This lets explicit env vars override KMS values (dev convenience).
func setEnvIfEmpty(key, value string) error {
	if existing, ok := lookupEnv(key); ok && existing != "" {
		return nil // already set, don't override
	}
	return setEnv(key, value)
}

// getToken returns a cached IAM access token, refreshing if expired.
func (c *Client) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid (with 60s margin).
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return c.accessToken, nil
	}

	// Exchange client credentials for a token.
	tokenURL := c.iamEndpoint + "/api/login/oauth/access_token"
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
		c.tokenExpiry = time.Now().Add(1 * time.Hour) // default 1h
	}

	return c.accessToken, nil
}
