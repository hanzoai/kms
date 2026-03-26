// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package compliance

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hanzoai/kms/mpc-node/store"
)

// AuditEntry represents a single immutable audit log record.
// Each entry's Hash includes the previous entry's hash, forming a tamper-evident chain.
type AuditEntry struct {
	Timestamp time.Time `json:"ts"`
	OrgSlug   string    `json:"org"`
	ActorID   string    `json:"actor"`
	Action    string    `json:"action"`    // read, write, delete, rotate, breakglass, escrow
	SecretKey string    `json:"key"`       // the secret key accessed
	Reason    string    `json:"reason"`    // required for breakglass
	SourceIP  string    `json:"ip"`
	UserAgent string    `json:"ua"`
	Hash      string    `json:"hash"`      // SHA-256 chain hash (tamper detection)
	PrevHash  string    `json:"prev_hash"` // previous entry hash (blockchain-style chain)
}

// AuditLog provides an append-only, hash-chained audit trail.
// Entries cannot be modified or deleted once written (WORM semantics).
type AuditLog struct {
	store *store.Store
}

// NewAuditLog creates a new audit log backed by the given store.
func NewAuditLog(s *store.Store) *AuditLog {
	return &AuditLog{store: s}
}

// Append writes a new audit entry to the log. The entry's timestamp, hash, and
// previous hash are set automatically. This is append-only; entries cannot be
// modified or deleted.
func (a *AuditLog) Append(entry AuditEntry) error {
	entry.Timestamp = time.Now().UTC()

	// Get the previous entry's hash for chaining.
	prevHash, err := a.lastHash(entry.OrgSlug)
	if err != nil {
		return fmt.Errorf("compliance/audit: get prev hash: %w", err)
	}
	entry.PrevHash = prevHash

	// Compute the chain hash: SHA-256(prev_hash || timestamp || org || actor || action || key || reason).
	entry.Hash = computeEntryHash(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("compliance/audit: marshal: %w", err)
	}

	if _, err := a.store.PutAuditEntry(entry.OrgSlug, data); err != nil {
		return fmt.Errorf("compliance/audit: put: %w", err)
	}
	return nil
}

// List returns audit entries for an org between since and until (inclusive).
func (a *AuditLog) List(orgSlug string, since, until time.Time) ([]AuditEntry, error) {
	raw, err := a.store.GetAuditEntries(orgSlug, 0)
	if err != nil {
		return nil, fmt.Errorf("compliance/audit: list: %w", err)
	}

	var entries []AuditEntry
	for _, data := range raw {
		var entry AuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, fmt.Errorf("compliance/audit: unmarshal: %w", err)
		}
		if !entry.Timestamp.Before(since) && !entry.Timestamp.After(until) {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// Verify checks the integrity of the entire audit chain for an org.
// Returns true if the chain is intact, false if tampering is detected.
func (a *AuditLog) Verify(orgSlug string) (bool, error) {
	raw, err := a.store.GetAuditEntries(orgSlug, 0)
	if err != nil {
		return false, fmt.Errorf("compliance/audit: verify: %w", err)
	}
	if len(raw) == 0 {
		return true, nil
	}

	prevHash := ""
	for i, data := range raw {
		var entry AuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return false, fmt.Errorf("compliance/audit: verify unmarshal entry %d: %w", i, err)
		}

		// Check that prev_hash matches the expected previous hash.
		if entry.PrevHash != prevHash {
			return false, nil
		}

		// Recompute hash and verify.
		expected := computeEntryHash(entry)
		if entry.Hash != expected {
			return false, nil
		}

		prevHash = entry.Hash
	}
	return true, nil
}

// Export serializes audit entries for an org in the specified format ("json" or "csv").
func (a *AuditLog) Export(orgSlug string, format string) ([]byte, error) {
	raw, err := a.store.GetAuditEntries(orgSlug, 0)
	if err != nil {
		return nil, fmt.Errorf("compliance/audit: export: %w", err)
	}

	var entries []AuditEntry
	for _, data := range raw {
		var entry AuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, fmt.Errorf("compliance/audit: export unmarshal: %w", err)
		}
		entries = append(entries, entry)
	}

	switch format {
	case "json":
		return json.MarshalIndent(entries, "", "  ")
	case "csv":
		return exportCSV(entries)
	default:
		return nil, fmt.Errorf("compliance/audit: unsupported export format %q", format)
	}
}

// lastHash returns the hash of the most recent audit entry for an org,
// or "" if no entries exist.
func (a *AuditLog) lastHash(orgSlug string) (string, error) {
	raw, err := a.store.GetAuditEntries(orgSlug, 0)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 {
		return "", nil
	}
	var last AuditEntry
	if err := json.Unmarshal(raw[len(raw)-1], &last); err != nil {
		return "", err
	}
	return last.Hash, nil
}

// computeEntryHash computes SHA-256(prev_hash || ts || org || actor || action || key || reason).
func computeEntryHash(e AuditEntry) string {
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write([]byte(e.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(e.OrgSlug))
	h.Write([]byte(e.ActorID))
	h.Write([]byte(e.Action))
	h.Write([]byte(e.SecretKey))
	h.Write([]byte(e.Reason))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// exportCSV renders audit entries as CSV bytes.
func exportCSV(entries []AuditEntry) ([]byte, error) {
	if len(entries) == 0 {
		return []byte("ts,org,actor,action,key,reason,ip,ua,hash,prev_hash\n"), nil
	}
	var buf []byte
	buf = append(buf, "ts,org,actor,action,key,reason,ip,ua,hash,prev_hash\n"...)
	for _, e := range entries {
		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			e.Timestamp.Format(time.RFC3339Nano),
			e.OrgSlug, e.ActorID, e.Action, e.SecretKey,
			e.Reason, e.SourceIP, e.UserAgent, e.Hash, e.PrevHash,
		)
		buf = append(buf, line...)
	}
	return buf, nil
}

var (
	ErrAuditTampered = errors.New("compliance/audit: chain integrity check failed")
)
