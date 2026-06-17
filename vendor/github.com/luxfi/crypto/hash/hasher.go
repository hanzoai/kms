// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hash

// Hasher is an interface to compute a hash value.
type Hasher interface {
	// Hash takes a string and computes its hash value.
	// Values must be computed deterministically.
	Hash([]byte) uint64
}
