// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package verify

import (
	"context"
	"errors"
	"fmt"

	"github.com/luxfi/ids"
)

var (
	ErrSameChainID      = errors.New("same chainID")
	ErrMismatchedNetIDs = errors.New("mismatched netIDs")
)

// ChainContext provides context for chain operations
type ChainContext struct {
	ChainID        ids.ID
	NetID          ids.ID
	ValidatorState ValidatorState
}

// ValidatorState provides validator state lookups
type ValidatorState interface {
	GetChainID(ctx context.Context, chainID ids.ID) (ids.ID, error)
}

// ConsensusValidatorState wraps the consensus context ValidatorState interface
type ConsensusValidatorState interface {
	GetChainID(chainID ids.ID) (ids.ID, error)
}

// SameNet verifies that the provided [ctx] was provided to a chain in the
// same chain as [peerChainID], but not the same chain. If this verification
// fails, a non-nil error will be returned.
func SameNet(ctx context.Context, chainCtx *ChainContext, peerChainID ids.ID) error {
	if peerChainID == chainCtx.ChainID {
		return ErrSameChainID
	}

	peerNetID, err := chainCtx.ValidatorState.GetChainID(ctx, peerChainID)
	if err != nil {
		return fmt.Errorf("failed to get net of %q: %w", peerChainID, err)
	}
	if chainCtx.NetID != peerNetID {
		return fmt.Errorf("%w; expected %q got %q", ErrMismatchedNetIDs, chainCtx.NetID, peerNetID)
	}
	return nil
}

// SameChain verifies that chainID and peerChainID are different chains.
// Returns ErrSameChainID if they are the same.
func SameChain(chainID, peerChainID ids.ID) error {
	if peerChainID == chainID {
		return ErrSameChainID
	}
	return nil
}
