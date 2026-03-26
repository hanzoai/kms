// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package hsm

import (
	"context"
	"errors"
	"fmt"

	"github.com/hanzoai/hsm"
)

var (
	ErrShardNotFound = errors.New("hsm: shard not found in vault")
)

// ShardStore provides HSM-backed storage for Shamir secret shares.
// Instead of storing raw shard bytes in ZapDB, shards are encrypted
// via the HSM KeyShareVault (AES-256-GCM, key derived from HSM password provider).
// Key material never exists in plaintext at rest.
type ShardStore struct {
	vault     *hsm.KeyShareVault
	nodeID    string
	threshold int
	total     int
}

// NewShardStore creates an HSM-backed shard store.
func NewShardStore(vault *hsm.KeyShareVault, nodeID string, threshold, total int) (*ShardStore, error) {
	if vault == nil {
		return nil, errors.New("hsm: vault is nil")
	}
	if nodeID == "" {
		return nil, errors.New("hsm: nodeID is required")
	}
	if threshold < 2 {
		return nil, errors.New("hsm: threshold must be >= 2")
	}
	if total < 3 {
		return nil, errors.New("hsm: total must be >= 3")
	}
	if threshold >= total {
		return nil, errors.New("hsm: threshold must be < total")
	}
	return &ShardStore{
		vault:     vault,
		nodeID:    nodeID,
		threshold: threshold,
		total:     total,
	}, nil
}

// shardID builds a unique vault key for an org's shard on this node.
func (s *ShardStore) shardID(orgSlug string) string {
	return fmt.Sprintf("%s/shard/%s", orgSlug, s.nodeID)
}

// StoreShard encrypts and stores a shard in the HSM vault.
func (s *ShardStore) StoreShard(ctx context.Context, orgSlug string, shardIndex int, shardBytes []byte) error {
	if len(shardBytes) == 0 {
		return errors.New("hsm: empty shard data")
	}

	meta := hsm.KeyShareMeta{
		Index:        shardIndex,
		Threshold:    s.threshold,
		TotalParties: s.total,
	}

	return s.vault.Store(ctx, s.shardID(orgSlug), shardBytes, meta)
}

// GetShard retrieves and decrypts a shard from the HSM vault.
func (s *ShardStore) GetShard(ctx context.Context, orgSlug string) ([]byte, *hsm.KeyShareMeta, error) {
	data, meta, err := s.vault.Load(ctx, s.shardID(orgSlug))
	if err != nil {
		if errors.Is(err, hsm.ErrKeyShareNotFound) {
			return nil, nil, ErrShardNotFound
		}
		return nil, nil, fmt.Errorf("hsm: load shard: %w", err)
	}
	return data, meta, nil
}

// DeleteShard removes a shard from the HSM vault.
func (s *ShardStore) DeleteShard(orgSlug string) {
	s.vault.Delete(s.shardID(orgSlug))
}

// ListShards returns all shard IDs stored in the vault.
func (s *ShardStore) ListShards() []string {
	return s.vault.List()
}

// NodeID returns the node identifier.
func (s *ShardStore) NodeID() string { return s.nodeID }

// Threshold returns the reconstruction threshold.
func (s *ShardStore) Threshold() int { return s.threshold }

// Total returns the total number of shard parties.
func (s *ShardStore) Total() int { return s.total }
