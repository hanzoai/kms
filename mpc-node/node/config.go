// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package node

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hanzoai/kms/mpc-node/compliance"
)

// Config holds the MPC node configuration.
type Config struct {
	// NodeID is a unique identifier for this node (e.g., "kms-mpc-0").
	NodeID string

	// DataDir is the path to the ZapDB data directory.
	DataDir string

	// EncryptionKey is the 32-byte key for ZapDB encryption at rest.
	EncryptionKey []byte

	// Threshold is the Shamir threshold (t).
	Threshold int

	// TotalNodes is the total number of MPC nodes (n).
	TotalNodes int

	// ListenAddr is the gRPC listen address (e.g., ":9651").
	ListenAddr string

	// Peers is the list of peer addresses (e.g., ["node2:9651", "node3:9651"]).
	Peers []string

	// Compliance configures the regulatory compliance module.
	// When Mode is ModeNone, compliance enforcement is disabled.
	Compliance compliance.Config
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
	if c.Threshold < 2 {
		return errors.New("config: threshold must be >= 2")
	}
	if c.TotalNodes < 3 {
		return errors.New("config: total_nodes must be >= 3")
	}
	if c.Threshold >= c.TotalNodes {
		return errors.New("config: threshold must be < total_nodes")
	}
	if c.ListenAddr == "" {
		return errors.New("config: listen_addr is required")
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
