// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

// Package hsm integrates hanzoai/hsm into the MPC node for hardware-backed
// signing and key share storage. When enterprise.hsm_enabled is true, all
// MPC ceremony signing is co-signed by the HSM and Shamir shards are stored
// in the HSM-encrypted KeyShareVault instead of raw ZapDB.
package hsm

import (
	"context"
	"errors"
	"fmt"

	"github.com/hanzoai/hsm"
	"github.com/hanzoai/kms/mpc-node/node"
)

var (
	ErrHSMDisabled       = errors.New("hsm: not enabled in enterprise config")
	ErrProviderMapping   = errors.New("hsm: unsupported provider mapping")
)

// Integration wraps hanzoai/hsm for MPC node usage.
// It provides:
//   - An HSM-backed Signer for MPC ceremony attestation
//   - A KeyShareVault for encrypted shard storage
//   - A ThresholdManager for combined vault + attesting signer
type Integration struct {
	manager   *hsm.ThresholdManager
	signer    hsm.Signer
	vault     *hsm.KeyShareVault
	provider  string
}

// NewFromConfig creates an HSM Integration from the MPC node's EnterpriseConfig.
// Returns ErrHSMDisabled if enterprise.hsm_enabled is false.
func NewFromConfig(cfg node.EnterpriseConfig) (*Integration, error) {
	if !cfg.HSMEnabled {
		return nil, ErrHSMDisabled
	}

	signerProvider, err := mapProvider(cfg.HSMProvider)
	if err != nil {
		return nil, err
	}

	signerConfig := make(map[string]string)
	if cfg.HSMSlotID != 0 {
		signerConfig["slot_id"] = fmt.Sprintf("%d", cfg.HSMSlotID)
	}

	threshCfg := hsm.ThresholdConfig{
		PasswordProvider: mapPasswordProvider(cfg.HSMProvider),
		SignerProvider:   signerProvider,
		SignerConfig:     signerConfig,
		AttestKeyID:      "mpc-node-attest",
	}

	mgr, err := hsm.NewThresholdManager(threshCfg)
	if err != nil {
		return nil, fmt.Errorf("hsm: create threshold manager: %w", err)
	}

	return &Integration{
		manager:  mgr,
		signer:   mgr.HSMSigner(),
		vault:    mgr.Vault(),
		provider: signerProvider,
	}, nil
}

// Signer returns the HSM signer for MPC ceremony attestation.
func (i *Integration) Signer() hsm.Signer { return i.signer }

// Vault returns the encrypted key share vault.
func (i *Integration) Vault() *hsm.KeyShareVault { return i.vault }

// ThresholdManager returns the underlying threshold manager.
func (i *Integration) ThresholdManager() *hsm.ThresholdManager { return i.manager }

// Provider returns the active HSM provider name.
func (i *Integration) Provider() string { return i.provider }

// Sign delegates to the HSM signer with the attestation key.
func (i *Integration) Sign(ctx context.Context, message []byte) ([]byte, error) {
	return i.signer.Sign(ctx, "mpc-node-attest", message)
}

// Verify delegates to the HSM signer with the attestation key.
func (i *Integration) Verify(ctx context.Context, message, signature []byte) (bool, error) {
	return i.signer.Verify(ctx, "mpc-node-attest", message, signature)
}

// mapProvider converts EnterpriseConfig.HSMProvider to hanzoai/hsm signer provider names.
func mapProvider(provider string) (string, error) {
	switch provider {
	case "cloudhsm":
		return "aws", nil
	case "pkcs11":
		// PKCS#11 maps to zymbit (our HSM hardware)
		return "zymbit", nil
	case "yubihsm":
		// YubiHSM uses local signer with hardware backing
		return "local", nil
	default:
		return "", fmt.Errorf("%w: %q (supported: cloudhsm, pkcs11, yubihsm)", ErrProviderMapping, provider)
	}
}

// mapPasswordProvider returns the appropriate password provider for a given HSM provider.
func mapPasswordProvider(provider string) string {
	switch provider {
	case "cloudhsm":
		return "aws"
	default:
		return "env"
	}
}
