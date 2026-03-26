// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package shard

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/hanzoai/kms/mpc-node/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := store.NewStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testMasterKey(t *testing.T) []byte {
	t.Helper()
	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatal(err)
	}
	return mk
}

func TestNewShardManager(t *testing.T) {
	s := testStore(t)
	tests := []struct {
		name    string
		t, n    int
		wantErr bool
	}{
		{"2-of-3", 2, 3, false},
		{"3-of-5", 3, 5, false},
		{"5-of-7", 5, 7, false},
		{"t too low", 1, 3, true},
		{"t >= n", 3, 3, true},
		{"n too low", 2, 2, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewShardManager(s, "node-1", tt.t, tt.n)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewShardManager(%d, %d) error = %v, wantErr %v", tt.t, tt.n, err, tt.wantErr)
			}
		})
	}
}

func TestBootstrapAndReconstruct(t *testing.T) {
	tests := []struct {
		name string
		t, n int
	}{
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"5-of-7", 5, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testStore(t)
			sm, err := NewShardManager(s, "node-1", tt.t, tt.n)
			if err != nil {
				t.Fatal(err)
			}

			masterKey := testMasterKey(t)
			shards, err := sm.Bootstrap("acme", masterKey)
			if err != nil {
				t.Fatal(err)
			}
			if len(shards) != tt.n {
				t.Fatalf("Bootstrap produced %d shards, want %d", len(shards), tt.n)
			}

			// Reconstruct with exactly t shards succeeds.
			reconstructed, err := sm.Reconstruct(shards[:tt.t])
			if err != nil {
				t.Fatalf("Reconstruct with t shards: %v", err)
			}
			if !bytes.Equal(reconstructed, masterKey) {
				t.Fatalf("reconstructed key does not match original")
			}

			// Reconstruct with all n shards also succeeds.
			reconstructed, err = sm.Reconstruct(shards)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reconstructed, masterKey) {
				t.Fatal("reconstruct with all shards: mismatch")
			}
		})
	}
}

func TestReconstructFailsWithTooFewShards(t *testing.T) {
	s := testStore(t)
	sm, err := NewShardManager(s, "node-1", 3, 5)
	if err != nil {
		t.Fatal(err)
	}

	masterKey := testMasterKey(t)
	shards, err := sm.Bootstrap("acme", masterKey)
	if err != nil {
		t.Fatal(err)
	}

	// t-1 = 2 shards should fail.
	_, err = sm.Reconstruct(shards[:2])
	if err != ErrNotEnoughShards {
		t.Fatalf("expected ErrNotEnoughShards, got %v", err)
	}
}

func TestReconstructDifferentSubsets(t *testing.T) {
	s := testStore(t)
	sm, err := NewShardManager(s, "node-1", 2, 5)
	if err != nil {
		t.Fatal(err)
	}

	masterKey := testMasterKey(t)
	shards, err := sm.Bootstrap("acme", masterKey)
	if err != nil {
		t.Fatal(err)
	}

	// Any 2 of 5 should reconstruct correctly.
	subsets := [][]int{
		{0, 1}, {0, 2}, {0, 3}, {0, 4},
		{1, 2}, {1, 3}, {1, 4},
		{2, 3}, {2, 4},
		{3, 4},
	}
	for _, idx := range subsets {
		subset := []Shard{shards[idx[0]], shards[idx[1]]}
		got, err := sm.Reconstruct(subset)
		if err != nil {
			t.Fatalf("subset %v: %v", idx, err)
		}
		if !bytes.Equal(got, masterKey) {
			t.Fatalf("subset %v: reconstructed key mismatch", idx)
		}
	}
}

func TestBootstrapCeremony(t *testing.T) {
	s := testStore(t)
	sm, err := NewShardManager(s, "node-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	masterKey := testMasterKey(t)
	result, err := sm.BootstrapCeremony("acme", masterKey, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Verify recovery hash.
	hash := sha256.Sum256(masterKey)
	if !bytes.Equal(result.RecoveryVerification, hash[:]) {
		t.Fatal("recovery verification hash mismatch")
	}

	// Verify local shard was stored.
	stored, err := sm.GetShard("acme")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, result.Shards[0].Value.Bytes()) {
		t.Fatal("stored shard does not match generated shard")
	}
}

func TestRotateCeremony(t *testing.T) {
	s := testStore(t)
	sm, err := NewShardManager(s, "node-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	masterKey := testMasterKey(t)

	// Initial bootstrap.
	orig, err := sm.BootstrapCeremony("acme", masterKey, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Rotate: same master key, new polynomial.
	rotated, err := sm.RotateCeremony("acme", masterKey, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Same recovery hash.
	if !bytes.Equal(orig.RecoveryVerification, rotated.RecoveryVerification) {
		t.Fatal("recovery hash changed after rotation")
	}

	// New shards should reconstruct to same master key.
	got, err := sm.Reconstruct(rotated.NewShards[:2])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, masterKey) {
		t.Fatal("rotated shards do not reconstruct to original master key")
	}

	// But shard values should differ (different random polynomial).
	// This is probabilistic but with overwhelming probability.
	allSame := true
	for i := range orig.Shards {
		if orig.Shards[i].Value.Cmp(rotated.NewShards[i].Value) != 0 {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatal("rotation did not change shard values — polynomial was not randomized")
	}
}
