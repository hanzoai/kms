// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package crypto

import (
	"crypto/rand"
)

// RandomBytes returns a slice of n random bytes from crypto/rand.
// In Go 1.26+, crypto/rand.Read always succeeds or panics.
func RandomBytes(n int) []byte {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return bytes
}
