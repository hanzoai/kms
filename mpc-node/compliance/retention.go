// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package compliance

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hanzoai/kms/mpc-node/store"
)

var (
	ErrRetentionActive   = errors.New("compliance/retention: record is under active retention and cannot be deleted")
	ErrRetentionNotFound = errors.New("compliance/retention: retention record not found")
)

// RetainedRecord represents a secret under regulatory retention.
type RetainedRecord struct {
	OrgSlug    string    `json:"org"`
	SecretKey  string    `json:"key"`
	RetainedAt time.Time `json:"retained_at"` // when retention was applied
	ExpiresAt  time.Time `json:"expires_at"`  // when retention expires
}

// RetentionManager enforces record retention policies (e.g., SEC 17a-4).
// Once a secret is marked as retained, it cannot be deleted until the
// retention period expires.
type RetentionManager struct {
	store          *store.Store
	retentionYears int
}

// NewRetentionManager creates a retention manager with the given retention period.
func NewRetentionManager(s *store.Store, retentionYears int) *RetentionManager {
	return &RetentionManager{
		store:          s,
		retentionYears: retentionYears,
	}
}

// MarkRetained marks a secret as subject to the retention policy.
// The secret cannot be deleted until retentionYears have elapsed.
func (rm *RetentionManager) MarkRetained(orgSlug, secretKey string) error {
	now := time.Now().UTC()
	record := RetainedRecord{
		OrgSlug:    orgSlug,
		SecretKey:  secretKey,
		RetainedAt: now,
		ExpiresAt:  now.AddDate(rm.retentionYears, 0, 0),
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("compliance/retention: marshal: %w", err)
	}

	return rm.store.PutRetention(orgSlug, secretKey, data)
}

// CanDelete checks if a secret's retention period has expired.
// Returns true if the secret can be safely deleted (no active retention or expired).
// Returns false if the secret is under active retention.
func (rm *RetentionManager) CanDelete(orgSlug, secretKey string) (bool, error) {
	data, err := rm.store.GetRetention(orgSlug, secretKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return true, nil // no retention record means it can be deleted
		}
		return false, fmt.Errorf("compliance/retention: get: %w", err)
	}

	var record RetainedRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return false, fmt.Errorf("compliance/retention: unmarshal: %w", err)
	}

	return time.Now().UTC().After(record.ExpiresAt), nil
}

// PreventDelete checks the retention policy and returns an error if deletion
// is not allowed. This is used as a pre-delete hook.
func (rm *RetentionManager) PreventDelete(orgSlug, secretKey string) error {
	canDelete, err := rm.CanDelete(orgSlug, secretKey)
	if err != nil {
		return err
	}
	if !canDelete {
		return ErrRetentionActive
	}
	return nil
}

// ListRetained returns all secrets under active retention for an org.
func (rm *RetentionManager) ListRetained(orgSlug string) ([]RetainedRecord, error) {
	keys, err := rm.store.ListRetentionKeys(orgSlug)
	if err != nil {
		return nil, fmt.Errorf("compliance/retention: list keys: %w", err)
	}

	now := time.Now().UTC()
	var active []RetainedRecord
	for _, key := range keys {
		data, err := rm.store.GetRetention(orgSlug, key)
		if err != nil {
			return nil, fmt.Errorf("compliance/retention: get %s: %w", key, err)
		}
		var record RetainedRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("compliance/retention: unmarshal %s: %w", key, err)
		}
		if now.Before(record.ExpiresAt) {
			active = append(active, record)
		}
	}
	return active, nil
}

// ExportRetained exports all retained records for regulatory examination.
// The records themselves are metadata only; actual secrets remain encrypted
// and require the escrow shard to decrypt.
func (rm *RetentionManager) ExportRetained(orgSlug string) ([]byte, error) {
	records, err := rm.ListRetained(orgSlug)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(records, "", "  ")
}
