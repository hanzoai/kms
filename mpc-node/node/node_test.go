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
	return testConfigWithTier(t, TierMPC)
}

func testConfigWithTier(t *testing.T, tier KMSTier) *Config {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		NodeID:        "test-node-1",
		DataDir:       t.TempDir(),
		EncryptionKey: key,
		Tier:          tier,
		ListenAddr:    ":0",
		Peers:         []string{"peer-1:9999", "peer-2:9999"},
	}
	// Set tier-appropriate defaults.
	switch tier {
	case TierStandard:
		// No threshold/nodes needed.
	case TierMPC:
		cfg.Threshold = 2
		cfg.TotalNodes = 3
	case TierTFHE:
		cfg.Threshold = 3
		cfg.TotalNodes = 5
	case TierSovereign:
		cfg.Threshold = 5
		cfg.TotalNodes = 7
	}
	return cfg
}

func TestConfigValidation(t *testing.T) {
	validKey := make([]byte, 32)
	rand.Read(validKey)

	tests := []struct {
		name    string
		modify  func(c *Config)
		wantErr bool
	}{
		{"valid mpc", func(c *Config) {}, false},
		{"empty node_id", func(c *Config) { c.NodeID = "" }, true},
		{"empty data_dir", func(c *Config) { c.DataDir = "" }, true},
		{"short encryption key", func(c *Config) { c.EncryptionKey = []byte("short") }, true},
		{"mpc threshold too low", func(c *Config) { c.Threshold = 1 }, true},
		{"mpc total_nodes too low", func(c *Config) { c.TotalNodes = 2 }, true},
		{"mpc threshold >= total", func(c *Config) { c.Threshold = 3; c.TotalNodes = 3 }, true},
		{"empty listen_addr", func(c *Config) { c.ListenAddr = "" }, true},
		{"standard tier no threshold needed", func(c *Config) {
			c.Tier = TierStandard
			c.Threshold = 0
			c.TotalNodes = 0
		}, false},
		{"tfhe tier threshold too low", func(c *Config) {
			c.Tier = TierTFHE
			c.Threshold = 2
			c.TotalNodes = 5
		}, true},
		{"tfhe tier nodes too low", func(c *Config) {
			c.Tier = TierTFHE
			c.Threshold = 3
			c.TotalNodes = 4
		}, true},
		{"tfhe tier valid", func(c *Config) {
			c.Tier = TierTFHE
			c.Threshold = 3
			c.TotalNodes = 5
		}, false},
		{"sovereign tier threshold too low", func(c *Config) {
			c.Tier = TierSovereign
			c.Threshold = 3
			c.TotalNodes = 7
		}, true},
		{"sovereign tier nodes too low", func(c *Config) {
			c.Tier = TierSovereign
			c.Threshold = 5
			c.TotalNodes = 6
		}, true},
		{"sovereign tier valid", func(c *Config) {
			c.Tier = TierSovereign
			c.Threshold = 5
			c.TotalNodes = 7
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				NodeID:        "node-1",
				DataDir:       t.TempDir(),
				EncryptionKey: validKey,
				Tier:          TierMPC,
				Threshold:     2,
				TotalNodes:    3,
				ListenAddr:    ":9999",
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
	// Simulate a 2-of-3 MPC-tier cluster lifecycle.
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
			Tier:          TierMPC,
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

func TestKMSTierString(t *testing.T) {
	tests := []struct {
		tier KMSTier
		want string
	}{
		{TierStandard, "standard"},
		{TierMPC, "mpc"},
		{TierTFHE, "tfhe"},
		{TierSovereign, "sovereign"},
		{KMSTier(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.tier.String(); got != tt.want {
			t.Errorf("KMSTier(%d).String() = %q, want %q", tt.tier, got, tt.want)
		}
	}
}

func TestParseKMSTier(t *testing.T) {
	tests := []struct {
		input   string
		want    KMSTier
		wantErr bool
	}{
		{"standard", TierStandard, false},
		{"mpc", TierMPC, false},
		{"tfhe", TierTFHE, false},
		{"sovereign", TierSovereign, false},
		{"invalid", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseKMSTier(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseKMSTier(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("ParseKMSTier(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestTierRequiresMPC(t *testing.T) {
	if TierStandard.RequiresMPC() {
		t.Error("TierStandard should not require MPC")
	}
	if !TierMPC.RequiresMPC() {
		t.Error("TierMPC should require MPC")
	}
	if !TierTFHE.RequiresMPC() {
		t.Error("TierTFHE should require MPC")
	}
	if !TierSovereign.RequiresMPC() {
		t.Error("TierSovereign should require MPC")
	}
}

func TestTierRequiresFHE(t *testing.T) {
	if TierStandard.RequiresFHE() {
		t.Error("TierStandard should not require FHE")
	}
	if TierMPC.RequiresFHE() {
		t.Error("TierMPC should not require FHE")
	}
	if !TierTFHE.RequiresFHE() {
		t.Error("TierTFHE should require FHE")
	}
	if !TierSovereign.RequiresFHE() {
		t.Error("TierSovereign should require FHE")
	}
}

func TestStandardTierNodeInit(t *testing.T) {
	cfg := testConfigWithTier(t, TierStandard)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()

	if n.Store == nil {
		t.Fatal("store should be initialized for standard tier")
	}
	if n.Shards != nil {
		t.Fatal("shard manager should be nil for standard tier")
	}
	if n.CRDT != nil {
		t.Fatal("CRDT should be nil for standard tier")
	}
}

func TestMPCTierSecretCRUDWithoutFHE(t *testing.T) {
	// MPC tier should support full secret CRUD without FHE.
	cfg := testConfigWithTier(t, TierMPC)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()

	// Verify no FHE.
	if n.CRDT != nil {
		t.Fatal("MPC tier should not have CRDT")
	}

	// Store a secret.
	secretData := []byte("encrypted-api-key-material")
	if err := n.Store.PutSecret("acme", "api-key", secretData); err != nil {
		t.Fatal(err)
	}

	// Retrieve the secret.
	got, err := n.Store.GetSecret("acme", "api-key")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secretData) {
		t.Fatalf("secret mismatch: got %x, want %x", got, secretData)
	}

	// List secrets.
	keys, err := n.Store.ListSecrets("acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "api-key" {
		t.Fatalf("ListSecrets = %v, want [api-key]", keys)
	}

	// Delete the secret.
	if err := n.Store.DeleteSecret("acme", "api-key"); err != nil {
		t.Fatal(err)
	}
	keys, err = n.Store.ListSecrets("acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("ListSecrets after delete = %v, want empty", keys)
	}
}

func TestMPCTierBootstrapAndCRUD(t *testing.T) {
	// Full MPC tier lifecycle: bootstrap + secret CRUD, no FHE involved.
	cfg := testConfigWithTier(t, TierMPC)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()

	// Bootstrap org.
	result, err := n.Bootstrap("acme", "admin-passphrase", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Shards) != 3 {
		t.Fatalf("want 3 shards, got %d", len(result.Shards))
	}

	// Store and retrieve a secret.
	if err := n.Store.PutSecret("acme", "db-pass", []byte("enc-db-pass")); err != nil {
		t.Fatal(err)
	}
	got, err := n.Store.GetSecret("acme", "db-pass")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("enc-db-pass")) {
		t.Fatal("secret mismatch")
	}
}

func TestStandardTierRejectsBootstrap(t *testing.T) {
	cfg := testConfigWithTier(t, TierStandard)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()

	_, err = n.Bootstrap("acme", "passphrase", 1)
	if err == nil {
		t.Fatal("standard tier should reject bootstrap")
	}
}

func TestStandardTierRejectsJoin(t *testing.T) {
	cfg := testConfigWithTier(t, TierStandard)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()

	err = n.Join("acme", []byte("shard-data"))
	if err == nil {
		t.Fatal("standard tier should reject join")
	}
}

func TestMPCTierRejectsSync(t *testing.T) {
	cfg := testConfigWithTier(t, TierMPC)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()

	err = n.Sync("acme")
	if err == nil {
		t.Fatal("MPC tier should reject CRDT sync")
	}
}

func TestMPCTierRejectsInitFHE(t *testing.T) {
	cfg := testConfigWithTier(t, TierMPC)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()

	err = n.InitFHE(nil)
	if err == nil {
		t.Fatal("MPC tier should reject InitFHE")
	}
}
