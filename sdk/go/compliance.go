// Copyright (C) 2020-2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kms

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// ComplianceMode for regulated industries.
type ComplianceMode int

const (
	ComplianceNone  ComplianceMode = iota
	ComplianceHIPAA                // Healthcare
	ComplianceSEC                  // SEC Rule 17a-4
	ComplianceFINRA                // FINRA
	ComplianceSOX                  // Sarbanes-Oxley
	ComplianceGDPR                 // EU
)

// RegulatorAccess controls how regulators can access escrowed material.
type RegulatorAccess int

const (
	// RegulatorWithOrgCooperation requires the org to participate in export.
	RegulatorWithOrgCooperation RegulatorAccess = iota
	// RegulatorUnilateral allows the regulator to export without org cooperation.
	RegulatorUnilateral
)

// ComplianceConfig configures regulatory compliance mode for an org.
type ComplianceConfig struct {
	// Mode is the compliance framework to enforce.
	Mode ComplianceMode `json:"mode"`

	// EscrowPubKey is the regulator's public key for the escrow shard.
	EscrowPubKey []byte `json:"escrow_pub_key"`

	// RetentionYears is the record retention period.
	RetentionYears int `json:"retention_years"`

	// WORMAuditLog enables an immutable (write-once-read-many) audit trail.
	WORMAuditLog bool `json:"worm_audit_log"`

	// BreakGlass enables emergency decryption (required for HIPAA).
	BreakGlass bool `json:"break_glass"`

	// RegulatorAccess controls how regulators can access escrowed material.
	RegulatorAccess RegulatorAccess `json:"regulator_access"`
}

// BreakGlassToken is a time-limited emergency decryption token.
type BreakGlassToken struct {
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
	SecretKeys []string  `json:"secret_keys"`
}

// AuditEntry is a single entry in the WORM audit log.
type AuditEntry struct {
	Timestamp time.Time `json:"ts"`
	ActorID   string    `json:"actor"`
	Action    string    `json:"action"`
	SecretKey string    `json:"key"`
	Reason    string    `json:"reason"`
	SourceIP  string    `json:"ip"`
}

// RetainedRecord is a secret under active regulatory retention.
type RetainedRecord struct {
	Key        string    `json:"key"`
	RetainedAt time.Time `json:"retained_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// RegulatorPackage is the encrypted export package for regulatory examination.
type RegulatorPackage struct {
	EncryptedSecrets []byte    `json:"encrypted_secrets"`
	EscrowMaterial   []byte    `json:"escrow_material"`   // wrapped with regulator's HPKE key
	AuditTrail       []byte    `json:"audit_trail"`       // chain-hashed audit entries
	ExportTimestamp  time.Time `json:"export_timestamp"`
}

// --- Compliance lifecycle ---

// enableComplianceRequest is the JSON body sent to the compliance enable endpoint.
type enableComplianceRequest struct {
	Mode            ComplianceMode  `json:"mode"`
	EscrowPubKey    []byte          `json:"escrow_pub_key"`
	RetentionYears  int             `json:"retention_years"`
	WORMAuditLog    bool            `json:"worm_audit_log"`
	BreakGlass      bool            `json:"break_glass"`
	RegulatorAccess RegulatorAccess `json:"regulator_access"`
}

// EnableCompliance activates compliance mode for this org.
// Creates an escrow shard wrapped with the regulator's public key.
// Must be called by org admin.
func (c *Client) EnableCompliance(cfg ComplianceConfig) error {
	if cfg.Mode == ComplianceNone {
		return fmt.Errorf("kms: compliance mode must not be ComplianceNone")
	}
	if len(cfg.EscrowPubKey) == 0 {
		return fmt.Errorf("kms: escrow public key is required")
	}
	if cfg.RetentionYears < 1 {
		return fmt.Errorf("kms: retention years must be at least 1")
	}

	payload := enableComplianceRequest{
		Mode:            cfg.Mode,
		EscrowPubKey:    cfg.EscrowPubKey,
		RetentionYears:  cfg.RetentionYears,
		WORMAuditLog:    cfg.WORMAuditLog,
		BreakGlass:      cfg.BreakGlass,
		RegulatorAccess: cfg.RegulatorAccess,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("kms: enable compliance: marshal: %w", err)
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance", url.PathEscape(c.orgSlug))
	if err := c.broadcastPost(path, data); err != nil {
		return fmt.Errorf("kms: enable compliance: %w", err)
	}
	return nil
}

// DisableCompliance removes compliance mode (if allowed by retention policy).
func (c *Client) DisableCompliance() error {
	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance", url.PathEscape(c.orgSlug))

	type result struct {
		err error
	}
	ch := make(chan result, len(c.nodes))
	for _, node := range c.nodes {
		go func(addr string) {
			ch <- result{err: c.deleteRequest(addr + path)}
		}(node)
	}

	var successes int
	var lastErr error
	for range c.nodes {
		r := <-ch
		if r.err != nil {
			lastErr = r.err
		} else {
			successes++
		}
	}

	if successes < c.threshold {
		return fmt.Errorf("kms: disable compliance: only %d of %d nodes responded (need %d): %w",
			successes, len(c.nodes), c.threshold, lastErr)
	}
	return nil
}

// --- Break-Glass (HIPAA) ---

// breakGlassRequest is the JSON body sent to request emergency access.
type breakGlassRequest struct {
	Reason     string   `json:"reason"`
	SecretKeys []string `json:"secret_keys"`
	DurationMs int64    `json:"duration_ms"`
}

// RequestBreakGlass requests emergency access to secrets.
// Creates a time-limited decryption token. Notifies org admins.
// Logged in WORM audit.
func (c *Client) RequestBreakGlass(reason string, secretKeys []string, duration time.Duration) (*BreakGlassToken, error) {
	if reason == "" {
		return nil, fmt.Errorf("kms: break-glass reason is required")
	}
	if len(secretKeys) == 0 {
		return nil, fmt.Errorf("kms: at least one secret key is required")
	}
	if duration <= 0 {
		return nil, fmt.Errorf("kms: break-glass duration must be positive")
	}

	payload := breakGlassRequest{
		Reason:     reason,
		SecretKeys: secretKeys,
		DurationMs: duration.Milliseconds(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("kms: break-glass: marshal: %w", err)
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance/break-glass", url.PathEscape(c.orgSlug))
	if err := c.broadcastPost(path, data); err != nil {
		return nil, fmt.Errorf("kms: break-glass: %w", err)
	}

	// Retrieve the generated token from the quorum.
	body, err := c.quorumGet(path)
	if err != nil {
		return nil, fmt.Errorf("kms: break-glass: get token: %w", err)
	}

	var token BreakGlassToken
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("kms: break-glass: unmarshal token: %w", err)
	}

	return &token, nil
}

// GetWithBreakGlass retrieves a secret using a break-glass token instead of CEK.
func (c *Client) GetWithBreakGlass(token string, key string) ([]byte, error) {
	if token == "" {
		return nil, fmt.Errorf("kms: break-glass token is required")
	}
	if key == "" {
		return nil, fmt.Errorf("kms: secret key is required")
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance/break-glass/%s/%s",
		url.PathEscape(c.orgSlug),
		url.PathEscape(token),
		url.PathEscape(key),
	)

	body, err := c.quorumGet(path)
	if err != nil {
		return nil, fmt.Errorf("kms: get with break-glass: %w", err)
	}

	var resp struct {
		Value []byte `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("kms: get with break-glass: unmarshal: %w", err)
	}

	return resp.Value, nil
}

// RevokeBreakGlass immediately revokes emergency access.
func (c *Client) RevokeBreakGlass(token string) error {
	if token == "" {
		return fmt.Errorf("kms: break-glass token is required")
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance/break-glass/%s",
		url.PathEscape(c.orgSlug),
		url.PathEscape(token),
	)

	type result struct {
		err error
	}
	ch := make(chan result, len(c.nodes))
	for _, node := range c.nodes {
		go func(addr string) {
			ch <- result{err: c.deleteRequest(addr + path)}
		}(node)
	}

	var successes int
	var lastErr error
	for range c.nodes {
		r := <-ch
		if r.err != nil {
			lastErr = r.err
		} else {
			successes++
		}
	}

	if successes < c.threshold {
		return fmt.Errorf("kms: revoke break-glass: only %d of %d nodes responded (need %d): %w",
			successes, len(c.nodes), c.threshold, lastErr)
	}
	return nil
}

// --- Audit Log ---

// AuditLog retrieves the WORM audit log for this org.
// Only org admins and compliance officers can access.
func (c *Client) AuditLog(since, until time.Time) ([]AuditEntry, error) {
	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance/audit?since=%d&until=%d",
		url.PathEscape(c.orgSlug),
		since.UnixMilli(),
		until.UnixMilli(),
	)

	body, err := c.quorumGet(path)
	if err != nil {
		return nil, fmt.Errorf("kms: audit log: %w", err)
	}

	var resp struct {
		Entries []AuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("kms: audit log: unmarshal: %w", err)
	}

	return resp.Entries, nil
}

// VerifyAuditLog verifies the tamper-evident chain integrity.
func (c *Client) VerifyAuditLog() (bool, error) {
	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance/audit/verify", url.PathEscape(c.orgSlug))

	body, err := c.quorumGet(path)
	if err != nil {
		return false, fmt.Errorf("kms: verify audit log: %w", err)
	}

	var resp struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, fmt.Errorf("kms: verify audit log: unmarshal: %w", err)
	}

	return resp.Valid, nil
}

// ExportAuditLog exports the audit log for regulatory examination.
// Supported formats: "csv" or "json".
func (c *Client) ExportAuditLog(format string) ([]byte, error) {
	if format != "csv" && format != "json" {
		return nil, fmt.Errorf("kms: unsupported audit log format %q (use \"csv\" or \"json\")", format)
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance/audit/export?format=%s",
		url.PathEscape(c.orgSlug),
		url.QueryEscape(format),
	)

	body, err := c.quorumGet(path)
	if err != nil {
		return nil, fmt.Errorf("kms: export audit log: %w", err)
	}

	return body, nil
}

// --- Retention ---

// retainRequest is the JSON body for marking secrets as retained.
type retainRequest struct {
	SecretKeys []string `json:"secret_keys"`
}

// MarkRetained marks secrets as subject to retention policy.
// They cannot be deleted until the retention period expires.
func (c *Client) MarkRetained(secretKeys []string) error {
	if len(secretKeys) == 0 {
		return fmt.Errorf("kms: at least one secret key is required")
	}

	payload := retainRequest{SecretKeys: secretKeys}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("kms: mark retained: marshal: %w", err)
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance/retained", url.PathEscape(c.orgSlug))
	if err := c.broadcastPost(path, data); err != nil {
		return fmt.Errorf("kms: mark retained: %w", err)
	}
	return nil
}

// ListRetained returns all secrets under active retention.
func (c *Client) ListRetained() ([]RetainedRecord, error) {
	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance/retained", url.PathEscape(c.orgSlug))

	body, err := c.quorumGet(path)
	if err != nil {
		return nil, fmt.Errorf("kms: list retained: %w", err)
	}

	var resp struct {
		Records []RetainedRecord `json:"records"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("kms: list retained: unmarshal: %w", err)
	}

	return resp.Records, nil
}

// --- Regulator Access ---

// regulatorExportRequest is the JSON body for requesting a regulator export.
type regulatorExportRequest struct {
	SecretKeys []string `json:"secret_keys"`
}

// RegulatorExport exports encrypted data for regulatory examination.
// The regulator uses their escrow shard to decrypt.
// Returns encrypted blob + escrow-wrapped decryption material.
func (c *Client) RegulatorExport(secretKeys []string) (*RegulatorPackage, error) {
	if len(secretKeys) == 0 {
		return nil, fmt.Errorf("kms: at least one secret key is required for export")
	}

	payload := regulatorExportRequest{SecretKeys: secretKeys}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("kms: regulator export: marshal: %w", err)
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/compliance/export", url.PathEscape(c.orgSlug))
	if err := c.broadcastPost(path, data); err != nil {
		return nil, fmt.Errorf("kms: regulator export: %w", err)
	}

	body, err := c.quorumGet(path)
	if err != nil {
		return nil, fmt.Errorf("kms: regulator export: get: %w", err)
	}

	var pkg RegulatorPackage
	if err := json.Unmarshal(body, &pkg); err != nil {
		return nil, fmt.Errorf("kms: regulator export: unmarshal: %w", err)
	}

	return &pkg, nil
}
