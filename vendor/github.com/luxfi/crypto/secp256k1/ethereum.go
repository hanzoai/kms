// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1

import (
	"crypto/ecdsa"

	"github.com/luxfi/crypto/common"
)

// PubkeyToAddress returns the Ethereum address for the given public key
func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := make([]byte, 65)
	pubBytes[0] = 0x04 // uncompressed point
	copy(pubBytes[1:33], p.X.Bytes())
	copy(pubBytes[33:65], p.Y.Bytes())

	// Ethereum address is last 20 bytes of Keccak256 hash of public key (excluding prefix)
	hash := Keccak256(pubBytes[1:])
	return common.BytesToAddress(hash[12:])
}
