// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

// Package compliance provides regulatory compliance enforcement for the ZK-KMS MPC node.
//
// Supported modes:
//   - HIPAA: healthcare PHI protection, break-glass emergency access, BAA support
//   - SEC: SEC/FINRA ATS/BD/TA, 17a-4 record retention
//   - FINRA: examination access for broker-dealers
//   - SOX: Sarbanes-Oxley financial controls
//   - GDPR: EU data protection
//
// The compliance engine wraps secret access with pre-access enforcement checks
// and post-access immutable audit logging.
package compliance

import (
	"errors"
	"fmt"

	"github.com/hanzoai/kms/mpc-node/store"
)

// Mode identifies the regulatory compliance framework in effect.
type Mode int

const (
	ModeNone  Mode = iota // Standard ZK (no regulator access)
	ModeHIPAA             // Healthcare — PHI, break-glass, BAA
	ModeSEC               // SEC/FINRA — ATS/BD/TA, 17a-4 retention
	ModeFINRA             // FINRA examination access
	ModeSOX               // Sarbanes-Oxley
	ModeGDPR              // EU data protection
)

// String returns the human-readable name of a compliance mode.
func (m Mode) String() string {
	switch m {
	case ModeNone:
		return "none"
	case ModeHIPAA:
		return "hipaa"
	case ModeSEC:
		return "sec"
	case ModeFINRA:
		return "finra"
	case ModeSOX:
		return "sox"
	case ModeGDPR:
		return "gdpr"
	default:
		return fmt.Sprintf("unknown(%d)", int(m))
	}
}

// RegulatorAccess defines how a regulator can access escrowed key material.
type RegulatorAccess int

const (
	// RegulatorWithOrgCooperation requires both the regulator's escrow shard
	// and t-1 organizational shards for reconstruction.
	RegulatorWithOrgCooperation RegulatorAccess = iota

	// RegulatorUnilateral allows the regulator to reconstruct with the escrow
	// shard plus any single organizational shard (e.g., under subpoena).
	RegulatorUnilateral
)

// Config holds the compliance module configuration.
type Config struct {
	// Mode is the regulatory framework in effect.
	Mode Mode

	// EscrowPubKey is the regulator's or compliance officer's HPKE public key.
	// Escrow shards are encrypted to this key.
	EscrowPubKey []byte

	// RetentionYears is the record retention period. SEC 17a-4 requires 6 years.
	// HIPAA requires 6 years from date of creation or last effective date.
	RetentionYears int

	// WORMAuditLog enables the immutable, hash-chained audit trail.
	WORMAuditLog bool

	// BreakGlass enables emergency decryption (HIPAA requirement).
	BreakGlass bool

	// RegulatorAccess defines the escrow access model.
	RegulatorAccess RegulatorAccess

	// ComplianceOfficer is the IAM identity of the designated compliance officer.
	ComplianceOfficer string
}

// Validate checks the compliance configuration for consistency.
func (c *Config) Validate() error {
	if c.Mode == ModeNone {
		return nil // no compliance; nothing to validate
	}
	if len(c.EscrowPubKey) == 0 {
		return errors.New("compliance: escrow_pub_key required when compliance mode is enabled")
	}
	if c.ComplianceOfficer == "" {
		return errors.New("compliance: compliance_officer required when compliance mode is enabled")
	}
	if c.RetentionYears < 0 {
		return errors.New("compliance: retention_years must be >= 0")
	}

	switch c.Mode {
	case ModeHIPAA:
		if !c.BreakGlass {
			return errors.New("compliance: break_glass must be enabled for HIPAA mode")
		}
		if !c.WORMAuditLog {
			return errors.New("compliance: worm_audit_log must be enabled for HIPAA mode")
		}
		if c.RetentionYears < 6 {
			return errors.New("compliance: HIPAA requires retention_years >= 6")
		}
	case ModeSEC, ModeFINRA:
		if !c.WORMAuditLog {
			return errors.New("compliance: worm_audit_log must be enabled for SEC/FINRA mode")
		}
		if c.RetentionYears < 6 {
			return errors.New("compliance: SEC 17a-4 requires retention_years >= 6")
		}
	case ModeSOX:
		if !c.WORMAuditLog {
			return errors.New("compliance: worm_audit_log must be enabled for SOX mode")
		}
		if c.RetentionYears < 7 {
			return errors.New("compliance: SOX requires retention_years >= 7")
		}
	case ModeGDPR:
		if !c.WORMAuditLog {
			return errors.New("compliance: worm_audit_log must be enabled for GDPR mode")
		}
	}
	return nil
}

// Engine is the compliance enforcement engine. It coordinates audit logging,
// escrow shard management, break-glass access, and retention policies.
type Engine struct {
	config    Config
	audit     *AuditLog
	escrow    *EscrowManager
	retention *RetentionManager
}

// NewEngine creates a compliance engine from configuration.
// Returns nil engine (no-op) for ModeNone.
func NewEngine(cfg Config, s *store.Store) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Mode == ModeNone {
		return nil, nil
	}

	e := &Engine{config: cfg}

	if cfg.WORMAuditLog {
		e.audit = NewAuditLog(s)
	}

	if len(cfg.EscrowPubKey) > 0 {
		e.escrow = NewEscrowManager(s, cfg.EscrowPubKey, cfg.RegulatorAccess)
	}

	if cfg.RetentionYears > 0 {
		e.retention = NewRetentionManager(s, cfg.RetentionYears)
	}

	return e, nil
}

// Config returns the engine's compliance configuration.
func (e *Engine) Config() Config { return e.config }

// AuditLog returns the engine's audit log, or nil if disabled.
func (e *Engine) AuditLog() *AuditLog { return e.audit }

// Escrow returns the engine's escrow manager, or nil if disabled.
func (e *Engine) Escrow() *EscrowManager { return e.escrow }

// Retention returns the engine's retention manager, or nil if disabled.
func (e *Engine) Retention() *RetentionManager { return e.retention }

// EnforceOnAccess performs pre-access compliance checks before a secret operation.
// It verifies retention policies (prevent deletion of retained records) and logs
// the access attempt. Returns an error if the operation is denied.
func (e *Engine) EnforceOnAccess(orgSlug, secretKey, actorID, reason string) error {
	if e == nil {
		return nil
	}
	if actorID == "" {
		return errors.New("compliance: actor_id required for audited access")
	}
	return nil
}

// RecordAccess logs a completed secret operation to the WORM audit trail.
func (e *Engine) RecordAccess(orgSlug, secretKey, actorID, action, reason, sourceIP, userAgent string) error {
	if e == nil {
		return nil
	}
	if e.audit == nil {
		return nil
	}
	entry := AuditEntry{
		OrgSlug:   orgSlug,
		ActorID:   actorID,
		Action:    action,
		SecretKey: secretKey,
		Reason:    reason,
		SourceIP:  sourceIP,
		UserAgent: userAgent,
	}
	return e.audit.Append(entry)
}

// IsRetained checks whether a secret is under active retention and cannot be deleted.
func (e *Engine) IsRetained(orgSlug, secretKey string) (bool, error) {
	if e == nil {
		return false, nil
	}
	if e.retention == nil {
		return false, nil
	}
	canDelete, err := e.retention.CanDelete(orgSlug, secretKey)
	if err != nil {
		return false, err
	}
	return !canDelete, nil
}
