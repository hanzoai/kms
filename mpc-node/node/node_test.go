// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package node

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func testConfig(t *testing.T) *Config {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return &Config{
		NodeID:        "test-node-1",
		DataDir:       t.TempDir(),
		EncryptionKey: key,
		Threshold:     2,
		TotalNodes:    3,
		ListenAddr:    ":0",
		Peers:         []string{"peer-1:9651", "peer-2:9651"},
	}
}

func TestConfigValidation(t *testing.T) {
	validKey := make([]byte, 32)
	rand.Read(validKey)

	tests := []struct {
		name    string
		modify  func(c *Config)
		wantErr bool
	}{
		{"valid", func(c *Config) {}, false},
		{"empty node_id", func(c *Config) { c.NodeID = "" }, true},
		{"empty data_dir", func(c *Config) { c.DataDir = "" }, true},
		{"short encryption key", func(c *Config) { c.EncryptionKey = []byte("short") }, true},
		{"threshold too low", func(c *Config) { c.Threshold = 1 }, true},
		{"total_nodes too low", func(c *Config) { c.TotalNodes = 2 }, true},
		{"threshold >= total", func(c *Config) { c.Threshold = 3; c.TotalNodes = 3 }, true},
		{"empty listen_addr", func(c *Config) { c.ListenAddr = "" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				NodeID:        "node-1",
				DataDir:       t.TempDir(),
				EncryptionKey: validKey,
				Threshold:     2,
				TotalNodes:    3,
				ListenAddr:    ":9651",
			}
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewNode(t *testing.T) {
	cfg := testConfig(t)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()

	if n.ID != cfg.NodeID {
		t.Fatalf("node ID = %s, want %s", n.ID, cfg.NodeID)
	}
	if n.Store == nil {
		t.Fatal("store is nil")
	}
	if n.Shards == nil {
		t.Fatal("shard manager is nil")
	}
}

func TestBootstrapAndJoinLifecycle(t *testing.T) {
	// Simulate a 2-of-3 cluster lifecycle.
	// Node 1 bootstraps, Nodes 2 and 3 join with their shards.
	configs := make([]*Config, 3)
	nodes := make([]*Node, 3)
	for i := 0; i < 3; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		configs[i] = &Config{
			NodeID:        fmt.Sprintf("node-%d", i+1),
			DataDir:       t.TempDir(),
			EncryptionKey: key,
			Threshold:     2,
			TotalNodes:    3,
			ListenAddr:    ":0",
		}
		var err error
		nodes[i], err = NewNode(configs[i])
		if err != nil {
			t.Fatal(err)
		}
		defer nodes[i].Shutdown()
	}

	// Node 1 bootstraps the org.
	result, err := nodes[0].Bootstrap("acme", "admin-passphrase", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Shards) != 3 {
		t.Fatalf("bootstrap produced %d shards, want 3", len(result.Shards))
	}

	// Nodes 2 and 3 join with their respective shards.
	for i := 1; i < 3; i++ {
		shardBytes := result.Shards[i].Value.Bytes()
		if err := nodes[i].Join("acme", shardBytes); err != nil {
			t.Fatalf("node %d join: %v", i+1, err)
		}
	}

	// Verify each node has its shard stored.
	for i := 0; i < 3; i++ {
		stored, err := nodes[i].Shards.GetShard("acme")
		if err != nil {
			t.Fatalf("node %d get shard: %v", i+1, err)
		}
		expected := result.Shards[i].Value.Bytes()
		if !bytes.Equal(stored, expected) {
			t.Fatalf("node %d shard mismatch", i+1)
		}
	}
}
