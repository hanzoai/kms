// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package shard

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// Ceremony coordinates key lifecycle operations:
// bootstrap (initial key generation), invite (distribute shard to new node),
// and rotate (re-key with new polynomial, same or different threshold).

// BootstrapResult holds the output of a bootstrap ceremony.
type BootstrapResult struct {
	Shards               []Shard // n shards to distribute
	RecoveryVerification []byte  // SHA-256(masterKey) for recovery verification
}

// BootstrapCeremony creates a new org's key material:
// splits masterKey into n shards, stores this node's shard locally.
func (sm *ShardManager) BootstrapCeremony(orgSlug string, masterKey []byte, localShardIndex int) (*BootstrapResult, error) {
	if localShardIndex < 1 || localShardIndex > sm.totalNodes {
		return nil, fmt.Errorf("shard: localShardIndex %d out of range [1, %d]", localShardIndex, sm.totalNodes)
	}

	shards, err := sm.Bootstrap(orgSlug, masterKey)
	if err != nil {
		return nil, fmt.Errorf("shard: bootstrap: %w", err)
	}

	// Store this node's shard locally.
	if err := sm.StoreShard(orgSlug, shards[localShardIndex-1]); err != nil {
		return nil, fmt.Errorf("shard: store local shard: %w", err)
	}

	hash := sha256.Sum256(masterKey)
	return &BootstrapResult{
		Shards:               shards,
		RecoveryVerification: hash[:],
	}, nil
}

// InviteNode stores a received shard from a bootstrap or rotation ceremony.
func (sm *ShardManager) InviteNode(orgSlug string, shardData []byte) error {
	if len(shardData) == 0 {
		return errors.New("shard: empty shard data")
	}
	return sm.store.PutShard(orgSlug, shardData)
}

// RotateResult holds the output of a rotation ceremony.
type RotateResult struct {
	NewShards            []Shard
	RecoveryVerification []byte
}

// RotateCeremony re-shards a reconstructed master key with a new random polynomial.
// The caller must have already reconstructed the master key from t shards.
func (sm *ShardManager) RotateCeremony(orgSlug string, masterKey []byte, localShardIndex int) (*RotateResult, error) {
	// Bootstrap with the same master key produces a new random polynomial.
	result, err := sm.BootstrapCeremony(orgSlug, masterKey, localShardIndex)
	if err != nil {
		return nil, err
	}
	return &RotateResult{
		NewShards:            result.Shards,
		RecoveryVerification: result.RecoveryVerification,
	}, nil
}
