// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package signer provides the Signer interface for BLS signatures.
package signer

import (
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/vm/components/verify"
)

// Signer is the interface for a BLS signer.
type Signer interface {
	verify.Verifiable

	// Key returns the public BLS key if it exists.
	// Note: [nil] will be returned if the key does not exist.
	// Invariant: Only called after [Verify] returns [nil].
	Key() *bls.PublicKey
}
