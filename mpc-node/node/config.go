// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package node

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hanzoai/kms/mpc-node/compliance"
)

// KMSTier identifies the security tier of the MPC node cluster.
//
//   - TierStandard:  Server-side AES-256-GCM encryption. No MPC threshold.
//   - TierMPC:       Customer keys + Shamir threshold + multisig (no FHE).
//   - TierTFHE:      MPC + FHE CRDT merge + ZK proofs.
//   - TierSovereign: TFHE + SessionVM onion routing + post-quantum on-chain.
type KMSTier int

const (
	TierStandard  KMSTier = iota // Server-side encryption, no MPC
	TierMPC                      // Customer keys + MPC threshold + multisig (no FHE)
	TierTFHE                     // MPC + FHE CRDT + ZK
	TierSovereign                // TFHE + SessionVM onion routing + PQ on-chain
)

// String returns the canonical name for a KMS tier.
func (t KMSTier) String() string {
	switch t {
	case TierStandard:
		return "standard"
	case TierMPC:
		return "mpc"
	case TierTFHE:
		return "tfhe"
	case TierSovereign:
		return "sovereign"
	default:
		return fmt.Sprintf("unknown(%d)", int(t))
	}
}

// ParseKMSTier converts a string to a KMSTier.
func ParseKMSTier(s string) (KMSTier, error) {
	switch s {
	case "standard":
		return TierStandard, nil
	case "mpc":
		return TierMPC, nil
	case "tfhe":
		return TierTFHE, nil
	case "sovereign":
		return TierSovereign, nil
	default:
		return 0, fmt.Errorf("config: unknown tier %q (must be standard, mpc, tfhe, or sovereign)", s)
	}
}

// RequiresMPC returns true if the tier uses Shamir threshold sharing.
func (t KMSTier) RequiresMPC() bool {
	return t >= TierMPC
}

// RequiresFHE returns true if the tier uses FHE CRDT synchronization.
func (t KMSTier) RequiresFHE() bool {
	return t >= TierTFHE
}

// Config holds the MPC node configuration.
type Config struct {
	// NodeID is a unique identifier for this node (e.g., "kms-mpc-0").
	NodeID string

	// DataDir is the path to the ZapDB data directory.
	DataDir string

	// EncryptionKey is the 32-byte key for ZapDB encryption at rest.
	EncryptionKey []byte

	// Tier is the KMS security tier. Determines which subsystems are initialized.
	Tier KMSTier `json:"tier"`

	// Threshold is the Shamir threshold (t). Required for TierMPC and above.
	Threshold int

	// TotalNodes is the total number of MPC nodes (n). Required for TierMPC and above.
	TotalNodes int

	// ListenAddr is the gRPC listen address (e.g., ":9999").
	ListenAddr string

	// Peers is the list of peer addresses (e.g., ["node2:9999", "node3:9999"]).
	Peers []string

	// Compliance configures the regulatory compliance module.
	// When Mode is ModeNone, compliance enforcement is disabled.
	Compliance compliance.Config

	// Enterprise configures enterprise features (multi-region, HSM, KMIP, etc.).
	// All fields are optional; zero values disable the respective feature.
	Enterprise EnterpriseConfig
}

// EnterpriseConfig holds enterprise-tier feature configuration.
// All fields are optional. Zero values disable the feature.
type EnterpriseConfig struct {
	// Multi-region replication
	Regions       []string `json:"regions,omitempty"`        // e.g., ["us-east-1", "eu-west-1", "ap-southeast-1"]
	PrimaryRegion string   `json:"primary_region,omitempty"` // Write primary; reads fan out to nearest

	// Key rotation policy
	AutoRotateInterval time.Duration `json:"auto_rotate_interval,omitempty"` // e.g., 90 days (2160h)
	RotationNotifyDays int           `json:"rotation_notify_days,omitempty"` // Notify n days before forced rotation

	// Access policies
	IPAllowList    []string      `json:"ip_allow_list,omitempty"`    // CIDR ranges allowed
	MFARequired    bool          `json:"mfa_required,omitempty"`     // Require MFA for secret access
	SessionTimeout time.Duration `json:"session_timeout,omitempty"` // Auto-lock CEK after inactivity

	// Audit sinks (external log destinations in addition to local ZapDB)
	AuditSinks []compliance.LogSinkConfig `json:"audit_sinks,omitempty"`

	// HSM integration
	HSMEnabled  bool   `json:"hsm_enabled,omitempty"`
	HSMProvider string `json:"hsm_provider,omitempty"` // "cloudhsm", "pkcs11", "yubihsm"
	HSMSlotID   int    `json:"hsm_slot_id,omitempty"`

	// KMIP (Key Management Interoperability Protocol)
	KMIPEnabled  bool   `json:"kmip_enabled,omitempty"`
	KMIPEndpoint string `json:"kmip_endpoint,omitempty"`
	KMIPCertFile string `json:"kmip_cert_file,omitempty"`
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.NodeID == "" {
		return errors.New("config: node_id is required")
	}
	if c.DataDir == "" {
		return errors.New("config: data_dir is required")
	}
	if len(c.EncryptionKey) != 32 {
		return fmt.Errorf("config: encryption_key must be 32 bytes, got %d", len(c.EncryptionKey))
	}
	if c.ListenAddr == "" {
		return errors.New("config: listen_addr is required")
	}
	if c.Tier < TierStandard || c.Tier > TierSovereign {
		return fmt.Errorf("config: invalid tier %d", c.Tier)
	}

	// MPC threshold validation applies to TierMPC and above.
	if c.Tier.RequiresMPC() {
		if c.Threshold < 2 {
			return errors.New("config: threshold must be >= 2 for mpc tier and above")
		}
		if c.TotalNodes < 3 {
			return errors.New("config: total_nodes must be >= 3 for mpc tier and above")
		}
		if c.Threshold >= c.TotalNodes {
			return errors.New("config: threshold must be < total_nodes")
		}

		// Higher tiers require stronger quorums.
		switch c.Tier {
		case TierTFHE:
			if c.Threshold < 3 {
				return errors.New("config: tfhe tier requires threshold >= 3")
			}
			if c.TotalNodes < 5 {
				return errors.New("config: tfhe tier requires total_nodes >= 5")
			}
		case TierSovereign:
			if c.Threshold < 5 {
				return errors.New("config: sovereign tier requires threshold >= 5")
			}
			if c.TotalNodes < 7 {
				return errors.New("config: sovereign tier requires total_nodes >= 7")
			}
		}
	}

	if err := c.Compliance.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := c.Enterprise.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// Validate checks the enterprise configuration for consistency.
func (e *EnterpriseConfig) Validate() error {
	if len(e.Regions) > 0 && e.PrimaryRegion == "" {
		return errors.New("enterprise: primary_region required when regions are configured")
	}
	if e.PrimaryRegion != "" {
		found := false
		for _, r := range e.Regions {
			if r == e.PrimaryRegion {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("enterprise: primary_region %q must be in regions list", e.PrimaryRegion)
		}
	}
	if e.AutoRotateInterval > 0 && e.AutoRotateInterval < 24*time.Hour {
		return errors.New("enterprise: auto_rotate_interval must be >= 24h")
	}
	if e.RotationNotifyDays < 0 {
		return errors.New("enterprise: rotation_notify_days must be >= 0")
	}
	for _, cidr := range e.IPAllowList {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("enterprise: invalid CIDR in ip_allow_list: %q: %w", cidr, err)
		}
	}
	if e.SessionTimeout > 0 && e.SessionTimeout < time.Minute {
		return errors.New("enterprise: session_timeout must be >= 1m")
	}
	for i := range e.AuditSinks {
		if err := e.AuditSinks[i].Validate(); err != nil {
			return fmt.Errorf("enterprise: audit_sinks[%d]: %w", i, err)
		}
	}
	if e.HSMEnabled && e.HSMProvider == "" {
		return errors.New("enterprise: hsm_provider required when hsm_enabled is true")
	}
	if e.HSMProvider != "" {
		switch e.HSMProvider {
		case "cloudhsm", "pkcs11", "yubihsm":
			// valid
		default:
			return fmt.Errorf("enterprise: unsupported hsm_provider %q (must be cloudhsm, pkcs11, or yubihsm)", e.HSMProvider)
		}
	}
	if e.KMIPEnabled && e.KMIPEndpoint == "" {
		return errors.New("enterprise: kmip_endpoint required when kmip_enabled is true")
	}
	if e.KMIPEnabled && e.KMIPCertFile != "" {
		if _, err := os.Stat(e.KMIPCertFile); err != nil {
			return fmt.Errorf("enterprise: kmip_cert_file not accessible: %w", err)
		}
	}
	return nil
}

// EnsureDataDir creates the data directory if it does not exist.
func (c *Config) EnsureDataDir() error {
	zapdbPath := filepath.Join(c.DataDir, "zapdb")
	return os.MkdirAll(zapdbPath, 0700)
}

// ZapDBPath returns the path to the ZapDB data directory.
func (c *Config) ZapDBPath() string {
	return filepath.Join(c.DataDir, "zapdb")
}
