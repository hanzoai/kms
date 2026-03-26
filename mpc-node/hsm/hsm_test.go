// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package hsm

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/hanzoai/hsm"
	"github.com/hanzoai/kms/mpc-node/node"
)

func setTestEnv(t *testing.T) {
	t.Helper()
	os.Setenv("LUX_MPC_PASSWORD", "test-mpc-password-2026")
	t.Cleanup(func() { os.Unsetenv("LUX_MPC_PASSWORD") })
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

func TestNewFromConfigDisabled(t *testing.T) {
	_, err := NewFromConfig(node.EnterpriseConfig{HSMEnabled: false})
	if err != ErrHSMDisabled {
		t.Fatalf("want ErrHSMDisabled, got %v", err)
	}
}

func TestNewFromConfigCloudHSM(t *testing.T) {
	setTestEnv(t)

	cfg := node.EnterpriseConfig{
		HSMEnabled:  true,
		HSMProvider: "cloudhsm",
	}
	integ, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig(cloudhsm): %v", err)
	}
	if integ.Provider() != "aws" {
		t.Errorf("provider = %q, want aws", integ.Provider())
	}
	if integ.Signer() == nil {
		t.Error("signer is nil")
	}
	if integ.Vault() == nil {
		t.Error("vault is nil")
	}
	if integ.ThresholdManager() == nil {
		t.Error("threshold manager is nil")
	}
}

func TestNewFromConfigPKCS11(t *testing.T) {
	setTestEnv(t)

	cfg := node.EnterpriseConfig{
		HSMEnabled:  true,
		HSMProvider: "pkcs11",
	}
	integ, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig(pkcs11): %v", err)
	}
	if integ.Provider() != "zymbit" {
		t.Errorf("provider = %q, want zymbit", integ.Provider())
	}
}

func TestNewFromConfigYubiHSM(t *testing.T) {
	setTestEnv(t)

	cfg := node.EnterpriseConfig{
		HSMEnabled:  true,
		HSMProvider: "yubihsm",
	}
	integ, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig(yubihsm): %v", err)
	}
	if integ.Provider() != "local" {
		t.Errorf("provider = %q, want local", integ.Provider())
	}
}

func TestNewFromConfigBadProvider(t *testing.T) {
	cfg := node.EnterpriseConfig{
		HSMEnabled:  true,
		HSMProvider: "nonexistent",
	}
	_, err := NewFromConfig(cfg)
	if err == nil {
		t.Error("want error for unsupported provider")
	}
}

func TestIntegrationSignVerify(t *testing.T) {
	setTestEnv(t)

	// yubihsm maps to local signer, which works without hardware
	cfg := node.EnterpriseConfig{
		HSMEnabled:  true,
		HSMProvider: "yubihsm",
	}
	integ, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}

	ctx := context.Background()
	msg := []byte("mpc ceremony message")

	sig, err := integ.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}

	ok, err := integ.Verify(ctx, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("valid signature should verify")
	}

	// Wrong message should fail
	ok, err = integ.Verify(ctx, []byte("tampered"), sig)
	if err != nil {
		t.Fatalf("Verify(tampered): %v", err)
	}
	if ok {
		t.Error("tampered message should not verify")
	}
}

// ---------------------------------------------------------------------------
// Provider Mapping Tests
// ---------------------------------------------------------------------------

func TestMapProvider(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"cloudhsm", "aws", false},
		{"pkcs11", "zymbit", false},
		{"yubihsm", "local", false},
		{"bad", "", true},
	}
	for _, tt := range tests {
		got, err := mapProvider(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("mapProvider(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("mapProvider(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMapPasswordProvider(t *testing.T) {
	if got := mapPasswordProvider("cloudhsm"); got != "aws" {
		t.Errorf("cloudhsm -> %q, want aws", got)
	}
	if got := mapPasswordProvider("pkcs11"); got != "env" {
		t.Errorf("pkcs11 -> %q, want env", got)
	}
	if got := mapPasswordProvider("yubihsm"); got != "env" {
		t.Errorf("yubihsm -> %q, want env", got)
	}
}

// ---------------------------------------------------------------------------
// ShardStore Tests
// ---------------------------------------------------------------------------

func testVault(t *testing.T) *hsm.KeyShareVault {
	t.Helper()
	setTestEnv(t)
	pw, err := hsm.NewPasswordProvider("env", nil)
	if err != nil {
		t.Fatal(err)
	}
	return hsm.NewKeyShareVault(pw, "")
}

func TestNewShardStoreValidation(t *testing.T) {
	vault := testVault(t)

	tests := []struct {
		name    string
		nodeID  string
		t, n    int
		wantErr bool
	}{
		{"valid", "node-1", 2, 3, false},
		{"valid 3-of-5", "node-2", 3, 5, false},
		{"nil vault", "node-1", 2, 3, true},
		{"empty nodeID", "", 2, 3, true},
		{"low threshold", "node-1", 1, 3, true},
		{"low total", "node-1", 2, 2, true},
		{"t >= n", "node-1", 3, 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := vault
			if tt.name == "nil vault" {
				v = nil
			}
			_, err := NewShardStore(v, tt.nodeID, tt.t, tt.n)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewShardStore() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestShardStoreStoreAndRetrieve(t *testing.T) {
	vault := testVault(t)
	store, err := NewShardStore(vault, "node-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	shardData := []byte("shamir-secret-share-value-0xdeadbeef")

	// Store
	if err := store.StoreShard(ctx, "acme", 1, shardData); err != nil {
		t.Fatalf("StoreShard: %v", err)
	}

	// Retrieve
	got, meta, err := store.GetShard(ctx, "acme")
	if err != nil {
		t.Fatalf("GetShard: %v", err)
	}
	if !bytes.Equal(got, shardData) {
		t.Errorf("GetShard() = %q, want %q", got, shardData)
	}
	if meta.Index != 1 {
		t.Errorf("meta.Index = %d, want 1", meta.Index)
	}
	if meta.Threshold != 2 {
		t.Errorf("meta.Threshold = %d, want 2", meta.Threshold)
	}
	if meta.TotalParties != 3 {
		t.Errorf("meta.TotalParties = %d, want 3", meta.TotalParties)
	}
}

func TestShardStoreNotFound(t *testing.T) {
	vault := testVault(t)
	store, err := NewShardStore(vault, "node-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.GetShard(context.Background(), "nonexistent")
	if err != ErrShardNotFound {
		t.Errorf("want ErrShardNotFound, got %v", err)
	}
}

func TestShardStoreDelete(t *testing.T) {
	vault := testVault(t)
	store, err := NewShardStore(vault, "node-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	store.StoreShard(ctx, "acme", 1, []byte("shard-data"))

	// Verify it exists
	_, _, err = store.GetShard(ctx, "acme")
	if err != nil {
		t.Fatalf("GetShard before delete: %v", err)
	}

	// Delete
	store.DeleteShard("acme")

	// Should be gone
	_, _, err = store.GetShard(ctx, "acme")
	if err != ErrShardNotFound {
		t.Errorf("after delete: want ErrShardNotFound, got %v", err)
	}
}

func TestShardStoreEmptyData(t *testing.T) {
	vault := testVault(t)
	store, err := NewShardStore(vault, "node-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	err = store.StoreShard(context.Background(), "acme", 1, []byte{})
	if err == nil {
		t.Error("want error for empty shard data")
	}
}

func TestShardStoreMultipleOrgs(t *testing.T) {
	vault := testVault(t)
	store, err := NewShardStore(vault, "node-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	orgs := map[string][]byte{
		"acme":   []byte("acme-shard-secret"),
		"globex": []byte("globex-shard-secret"),
		"initech": []byte("initech-shard-secret"),
	}

	// Store all
	for org, data := range orgs {
		if err := store.StoreShard(ctx, org, 1, data); err != nil {
			t.Fatalf("StoreShard(%s): %v", org, err)
		}
	}

	// Retrieve and verify each
	for org, want := range orgs {
		got, _, err := store.GetShard(ctx, org)
		if err != nil {
			t.Fatalf("GetShard(%s): %v", org, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("GetShard(%s) = %q, want %q", org, got, want)
		}
	}
}

func TestShardStoreOverwrite(t *testing.T) {
	vault := testVault(t)
	store, err := NewShardStore(vault, "node-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Store version 1
	store.StoreShard(ctx, "acme", 1, []byte("shard-v1"))

	// Overwrite with version 2 (key rotation)
	store.StoreShard(ctx, "acme", 1, []byte("shard-v2"))

	got, _, err := store.GetShard(ctx, "acme")
	if err != nil {
		t.Fatalf("GetShard: %v", err)
	}
	if string(got) != "shard-v2" {
		t.Errorf("got %q, want shard-v2", got)
	}
}

func TestShardStoreAccessors(t *testing.T) {
	vault := testVault(t)
	store, err := NewShardStore(vault, "kms-mpc-0", 3, 5)
	if err != nil {
		t.Fatal(err)
	}

	if store.NodeID() != "kms-mpc-0" {
		t.Errorf("NodeID = %q", store.NodeID())
	}
	if store.Threshold() != 3 {
		t.Errorf("Threshold = %d", store.Threshold())
	}
	if store.Total() != 5 {
		t.Errorf("Total = %d", store.Total())
	}
}

func TestShardStoreListShards(t *testing.T) {
	vault := testVault(t)
	store, err := NewShardStore(vault, "node-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	store.StoreShard(ctx, "org-a", 1, []byte("shard-a"))
	store.StoreShard(ctx, "org-b", 2, []byte("shard-b"))

	ids := store.ListShards()
	if len(ids) != 2 {
		t.Errorf("ListShards() returned %d entries, want 2", len(ids))
	}
}

// ---------------------------------------------------------------------------
// End-to-end: Integration + ShardStore
// ---------------------------------------------------------------------------

func TestEndToEndHSMShardStorage(t *testing.T) {
	setTestEnv(t)

	// Create integration with local signer (yubihsm -> local for testing)
	cfg := node.EnterpriseConfig{
		HSMEnabled:  true,
		HSMProvider: "yubihsm",
	}
	integ, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}

	// Create shard store backed by the integration's vault
	store, err := NewShardStore(integ.Vault(), "kms-mpc-0", 2, 3)
	if err != nil {
		t.Fatalf("NewShardStore: %v", err)
	}

	ctx := context.Background()

	// Store a shard
	shardData := []byte("shamir-polynomial-evaluation-at-x1")
	if err := store.StoreShard(ctx, "hanzo", 1, shardData); err != nil {
		t.Fatalf("StoreShard: %v", err)
	}

	// Retrieve it
	got, meta, err := store.GetShard(ctx, "hanzo")
	if err != nil {
		t.Fatalf("GetShard: %v", err)
	}
	if !bytes.Equal(got, shardData) {
		t.Fatal("shard data mismatch")
	}
	if meta.Threshold != 2 || meta.TotalParties != 3 {
		t.Errorf("meta = %+v", meta)
	}

	// Sign and verify with the HSM signer (attestation)
	msg := []byte("ceremony-round-1")
	sig, err := integ.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := integ.Verify(ctx, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("attestation should verify")
	}
}
