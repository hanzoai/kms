// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package compliance

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrBreakGlassDisabled = errors.New("compliance/breakglass: break-glass not enabled")
	ErrBreakGlassReason   = errors.New("compliance/breakglass: reason is required")
	ErrBreakGlassExpired  = errors.New("compliance/breakglass: token has expired")
	ErrBreakGlassNotFound = errors.New("compliance/breakglass: token not found")
	ErrBreakGlassNoKeys   = errors.New("compliance/breakglass: at least one secret key required")
)

// BreakGlassRequest represents a request for emergency decryption access.
type BreakGlassRequest struct {
	OrgSlug    string        // org requesting emergency access
	ActorID    string        // who is requesting (e.g., emergency physician)
	Reason     string        // required justification
	SecretKeys []string      // which secrets to access
	Duration   time.Duration // how long the temporary access lasts
}

// BreakGlassToken represents an active emergency access grant.
type BreakGlassToken struct {
	Token      string    `json:"token"`
	OrgSlug    string    `json:"org"`
	ActorID    string    `json:"actor"`
	Reason     string    `json:"reason"`
	SecretKeys []string  `json:"keys"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// RequestBreakGlass creates a time-limited decryption token for emergency access.
// This is required for HIPAA compliance: emergency physicians must be able to
// access PHI when normal authorization channels are unavailable.
//
// The request is logged to the WORM audit trail, and org admins are expected to
// be notified via an external notification system.
func (e *Engine) RequestBreakGlass(req BreakGlassRequest) (*BreakGlassToken, error) {
	if e == nil {
		return nil, ErrBreakGlassDisabled
	}
	if !e.config.BreakGlass {
		return nil, ErrBreakGlassDisabled
	}
	if req.Reason == "" {
		return nil, ErrBreakGlassReason
	}
	if len(req.SecretKeys) == 0 {
		return nil, ErrBreakGlassNoKeys
	}
	if req.Duration <= 0 {
		req.Duration = 1 * time.Hour // default: 1 hour emergency window
	}

	// Generate a cryptographically random token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("compliance/breakglass: generate token: %w", err)
	}
	tokenStr := hex.EncodeToString(tokenBytes)

	now := time.Now().UTC()
	bgToken := &BreakGlassToken{
		Token:      tokenStr,
		OrgSlug:    req.OrgSlug,
		ActorID:    req.ActorID,
		Reason:     req.Reason,
		SecretKeys: req.SecretKeys,
		CreatedAt:  now,
		ExpiresAt:  now.Add(req.Duration),
	}

	// Persist the token.
	data, err := json.Marshal(bgToken)
	if err != nil {
		return nil, fmt.Errorf("compliance/breakglass: marshal token: %w", err)
	}
	if err := e.audit.store.PutBreakGlass(tokenStr, data); err != nil {
		return nil, fmt.Errorf("compliance/breakglass: store token: %w", err)
	}

	// Log to the WORM audit trail.
	if e.audit != nil {
		for _, key := range req.SecretKeys {
			entry := AuditEntry{
				OrgSlug:   req.OrgSlug,
				ActorID:   req.ActorID,
				Action:    "breakglass",
				SecretKey: key,
				Reason:    req.Reason,
			}
			if err := e.audit.Append(entry); err != nil {
				return nil, fmt.Errorf("compliance/breakglass: audit: %w", err)
			}
		}
	}

	return bgToken, nil
}

// ValidateBreakGlass checks if a break-glass token is valid and not expired.
// Returns the token details if valid.
func (e *Engine) ValidateBreakGlass(token string) (*BreakGlassToken, error) {
	if e == nil {
		return nil, ErrBreakGlassDisabled
	}
	if !e.config.BreakGlass {
		return nil, ErrBreakGlassDisabled
	}

	data, err := e.audit.store.GetBreakGlass(token)
	if err != nil {
		return nil, ErrBreakGlassNotFound
	}

	var bgToken BreakGlassToken
	if err := json.Unmarshal(data, &bgToken); err != nil {
		return nil, fmt.Errorf("compliance/breakglass: unmarshal: %w", err)
	}

	if time.Now().UTC().After(bgToken.ExpiresAt) {
		return nil, ErrBreakGlassExpired
	}

	return &bgToken, nil
}

// RevokeBreakGlass immediately revokes an emergency access token.
func (e *Engine) RevokeBreakGlass(token string) error {
	if e == nil {
		return ErrBreakGlassDisabled
	}
	if !e.config.BreakGlass {
		return ErrBreakGlassDisabled
	}

	// Verify the token exists before revoking.
	data, err := e.audit.store.GetBreakGlass(token)
	if err != nil {
		return ErrBreakGlassNotFound
	}

	// Log the revocation.
	if e.audit != nil {
		var bgToken BreakGlassToken
		if err := json.Unmarshal(data, &bgToken); err == nil {
			entry := AuditEntry{
				OrgSlug:   bgToken.OrgSlug,
				ActorID:   bgToken.ActorID,
				Action:    "breakglass-revoke",
				SecretKey: "",
				Reason:    "token revoked",
			}
			if err := e.audit.Append(entry); err != nil {
				return fmt.Errorf("compliance/breakglass: audit revoke: %w", err)
			}
		}
	}

	return e.audit.store.DeleteBreakGlass(token)
}
