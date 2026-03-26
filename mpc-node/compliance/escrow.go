// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package compliance

import (
	"errors"
	"fmt"
	"math/big"

	mpcCrypto "github.com/hanzoai/kms/mpc-node/crypto"
	"github.com/hanzoai/kms/mpc-node/shard"
	"github.com/hanzoai/kms/mpc-node/store"
)

var (
	ErrEscrowKeyMissing    = errors.New("compliance/escrow: escrow public key not configured")
	ErrEscrowShardMissing  = errors.New("compliance/escrow: escrow shard not found")
	ErrInsufficientShards  = errors.New("compliance/escrow: insufficient shards for reconstruction")
)

// EscrowManager handles regulator escrow shard creation, storage, and reconstruction.
// When compliance is enabled, an additional Shamir shard is generated during key
// ceremonies and encrypted (wrapped) with the regulator's HPKE public key.
type EscrowManager struct {
	store     *store.Store
	escrowKey []byte          // regulator's HPKE public key
	access    RegulatorAccess // cooperation vs unilateral
}

// NewEscrowManager creates an escrow manager with the regulator's public key.
func NewEscrowManager(s *store.Store, escrowPubKey []byte, access RegulatorAccess) *EscrowManager {
	return &EscrowManager{
		store:     s,
		escrowKey: escrowPubKey,
		access:    access,
	}
}

// CreateEscrowShard generates an additional Shamir shard from the master key,
// wraps it with the regulator's HPKE public key, and stores it in ZapDB.
//
// The escrow shard is evaluated at x = totalNodes + 1 (one beyond the normal
// shard indices) so it does not conflict with any operational shard.
func (em *EscrowManager) CreateEscrowShard(orgSlug string, masterKey []byte, threshold, totalNodes int) error {
	if len(em.escrowKey) == 0 {
		return ErrEscrowKeyMissing
	}

	// Create a temporary shard manager to generate the polynomial.
	// We generate n+1 shards and take the last one as the escrow shard.
	sm, err := shard.NewShardManager(em.store, "escrow-gen", threshold, totalNodes+1)
	if err != nil {
		return fmt.Errorf("compliance/escrow: create shard manager: %w", err)
	}

	shards, err := sm.Bootstrap(orgSlug, masterKey)
	if err != nil {
		return fmt.Errorf("compliance/escrow: bootstrap: %w", err)
	}

	// The escrow shard is the (n+1)th shard.
	escrowShard := shards[totalNodes]
	escrowBytes := escrowShard.Value.Bytes()

	// Wrap with regulator's HPKE public key.
	wrapped, err := mpcCrypto.WrapCEK(escrowBytes, em.escrowKey)
	if err != nil {
		return fmt.Errorf("compliance/escrow: wrap shard: %w", err)
	}

	if err := em.store.PutEscrowShard(orgSlug, wrapped); err != nil {
		return fmt.Errorf("compliance/escrow: store shard: %w", err)
	}

	return nil
}

// GetWrappedEscrowShard retrieves the HPKE-wrapped escrow shard for an org.
// Only the holder of the regulator's private key can unwrap it.
func (em *EscrowManager) GetWrappedEscrowShard(orgSlug string) ([]byte, error) {
	wrapped, err := em.store.GetEscrowShard(orgSlug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrEscrowShardMissing
		}
		return nil, fmt.Errorf("compliance/escrow: get shard: %w", err)
	}
	return wrapped, nil
}

// RegulatorReconstruct allows a regulator to reconstruct the master key using
// their unwrapped escrow shard plus organizational shards.
//
// In RegulatorWithOrgCooperation mode: requires the escrow shard + (threshold - 1) org shards.
// In RegulatorUnilateral mode: requires the escrow shard + any 1 org shard.
func (em *EscrowManager) RegulatorReconstruct(orgSlug string, regulatorShard []byte, orgShards [][]byte, threshold int) ([]byte, error) {
	requiredOrgShards := threshold - 1
	if em.access == RegulatorUnilateral {
		requiredOrgShards = 1
	}

	if len(orgShards) < requiredOrgShards {
		return nil, fmt.Errorf("%w: need %d org shards, got %d", ErrInsufficientShards, requiredOrgShards, len(orgShards))
	}

	// Build the shard set for Lagrange interpolation.
	// Escrow shard has a high index to avoid collision with operational shards.
	var allShards []shard.Shard
	allShards = append(allShards, shard.Shard{
		Index: 999, // escrow shard index (arbitrary, distinct from 1..n)
		Value: new(big.Int).SetBytes(regulatorShard),
	})

	for i, s := range orgShards {
		if i >= requiredOrgShards {
			break
		}
		allShards = append(allShards, shard.Shard{
			Index: i + 1,
			Value: new(big.Int).SetBytes(s),
		})
	}

	// Use the shard manager's Reconstruct with the combined shards.
	totalForReconstruct := requiredOrgShards + 1
	sm, err := shard.NewShardManager(em.store, "escrow-reconstruct", totalForReconstruct, totalForReconstruct+1)
	if err != nil {
		return nil, fmt.Errorf("compliance/escrow: create reconstruct manager: %w", err)
	}

	return sm.Reconstruct(allShards)
}
