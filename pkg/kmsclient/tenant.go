package kmsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Secret is the spec-shape secret metadata (no value in list responses).
type Secret struct {
	SecretID   string            `json:"secretId"`
	TenantID   string            `json:"tenantId"`
	Path       string            `json:"path"`
	Name       string            `json:"name"`
	SecretType string            `json:"secretType,omitempty"`
	Status     string            `json:"status,omitempty"`
	Version    int               `json:"version,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	CreatedAt  string            `json:"createdAt,omitempty"`
	UpdatedAt  string            `json:"updatedAt,omitempty"`
	RotatedAt  string            `json:"rotatedAt,omitempty"`
	Value      string            `json:"value,omitempty"`
}

// SecretVersion is one immutable version of a secret.
type SecretVersion struct {
	Version     int    `json:"version"`
	Status      string `json:"status"`
	CreatedAt   string `json:"createdAt,omitempty"`
	DestroyedAt string `json:"destroyedAt,omitempty"`
}

// ReadSecret fetches a secret by its canonical secretId, returning metadata +
// plaintext value. Call `GetByID(ctx, id)` when you only need the value.
func (c *Client) ReadSecret(ctx context.Context, secretID string) (*Secret, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/secrets/%s", c.endpoint, url.PathEscape(secretID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("kmsclient: secret %s not found", secretID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kmsclient: status %d: %s", resp.StatusCode, body)
	}
	var out Secret
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("kmsclient: decode: %w", err)
	}
	return &out, nil
}

// GetByID returns the plaintext value for the given secretId.
func (c *Client) GetByID(ctx context.Context, secretID string) (string, error) {
	s, err := c.ReadSecret(ctx, secretID)
	if err != nil {
		return "", err
	}
	return s.Value, nil
}

// UpdateSecret replaces the value for a given secret (appends a new version).
func (c *Client) UpdateSecret(ctx context.Context, secretID, value string, metadata map[string]string) (*Secret, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/secrets/%s", c.endpoint, url.PathEscape(secretID))
	payload, _ := json.Marshal(map[string]any{"value": value, "metadata": metadata})
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kmsclient: status %d: %s", resp.StatusCode, body)
	}
	var out Secret
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("kmsclient: decode: %w", err)
	}
	return &out, nil
}

// DeleteByID removes a secret by its canonical id.
func (c *Client) DeleteByID(ctx context.Context, secretID string) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/secrets/%s", c.endpoint, url.PathEscape(secretID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("kmsclient: status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// ListVersions returns the version history for a secret (values redacted).
func (c *Client) ListVersions(ctx context.Context, secretID string) ([]SecretVersion, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/secrets/%s/versions", c.endpoint, url.PathEscape(secretID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
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
		Items []SecretVersion `json:"items"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, fmt.Errorf("kmsclient: decode: %w", err)
	}
	return wrap.Items, nil
}

// RotateSecret appends a new version with an explicit new value. If
// idempotencyKey is non-empty, repeated calls with the same key are no-ops.
func (c *Client) RotateSecret(ctx context.Context, secretID, newValue, idempotencyKey string) (*SecretVersion, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/secrets/%s/rotate", c.endpoint, url.PathEscape(secretID))
	payload, _ := json.Marshal(map[string]string{"newValue": newValue})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kmsclient: status %d: %s", resp.StatusCode, body)
	}
	var out struct {
		SecretID string `json:"secretId"`
		Version  int    `json:"version"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("kmsclient: decode: %w", err)
	}
	return &SecretVersion{Version: out.Version, Status: "active"}, nil
}

// Tenant surface --------------------------------------------------------

// Tenant is the tenant metadata record.
type Tenant struct {
	TenantID        string   `json:"tenantId"`
	Name            string   `json:"name"`
	EntityType      string   `json:"entityType"`
	Environment     string   `json:"environment"`
	AllowedServices []string `json:"allowedServices,omitempty"`
	AllowedChains   []string `json:"allowedChains,omitempty"`
	CreatedAt       string   `json:"createdAt,omitempty"`
	UpdatedAt       string   `json:"updatedAt,omitempty"`
}

// GetTenant returns the tenant record for the given id.
func (c *Client) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/tenants/%s", c.endpoint, url.PathEscape(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("kmsclient: tenant %s not found", tenantID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kmsclient: status %d: %s", resp.StatusCode, body)
	}
	var out Tenant
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("kmsclient: decode: %w", err)
	}
	return &out, nil
}

// TenantConfig is the bindings + feature flag record.
type TenantConfig struct {
	TenantID     string          `json:"tenantId"`
	Bindings     map[string]any  `json:"bindings,omitempty"`
	FeatureFlags map[string]bool `json:"featureFlags,omitempty"`
	UpdatedAt    string          `json:"updatedAt,omitempty"`
}

// GetTenantConfig returns the current config for a tenant.
func (c *Client) GetTenantConfig(ctx context.Context, tenantID string) (*TenantConfig, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/tenants/%s/config", c.endpoint, url.PathEscape(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
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
	var out TenantConfig
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("kmsclient: decode: %w", err)
	}
	return &out, nil
}

// PutTenantConfig replaces the config for a tenant (admin only).
func (c *Client) PutTenantConfig(ctx context.Context, cfg *TenantConfig) (*TenantConfig, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/tenants/%s/config", c.endpoint, url.PathEscape(cfg.TenantID))
	payload, _ := json.Marshal(cfg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kmsclient: status %d: %s", resp.StatusCode, body)
	}
	var out TenantConfig
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("kmsclient: decode: %w", err)
	}
	return &out, nil
}

// Integration is a per-tenant provider binding.
type Integration struct {
	IntegrationID string         `json:"integrationId"`
	TenantID      string         `json:"tenantId"`
	Provider      string         `json:"provider"`
	Status        string         `json:"status"`
	SecretRefs    []string       `json:"secretRefs,omitempty"`
	Config        map[string]any `json:"config,omitempty"`
	CreatedAt     string         `json:"createdAt,omitempty"`
}

// ListIntegrations returns the tenant's integration bindings.
func (c *Client) ListIntegrations(ctx context.Context, tenantID, provider string) ([]Integration, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("kmsclient: auth: %w", err)
	}
	u := fmt.Sprintf("%s/v1/kms/tenants/%s/integrations", c.endpoint, url.PathEscape(tenantID))
	if provider != "" {
		u += "?provider=" + url.QueryEscape(provider)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
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
		Items []Integration `json:"items"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, fmt.Errorf("kmsclient: decode: %w", err)
	}
	return wrap.Items, nil
}
