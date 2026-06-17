// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

//go:build gofuzz || !cgo
// +build gofuzz !cgo

package secp256k1

import (
	"math/big"
)

// ScalarMult implements elliptic curve scalar multiplication using double-and-add
func (bitCurve *BitCurve) ScalarMult(Bx, By *big.Int, scalar []byte) (*big.Int, *big.Int) {
	// Convert scalar to big.Int
	k := new(big.Int).SetBytes(scalar)

	// Handle special cases
	if k.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	// Use the double-and-add algorithm
	// Start with the identity point (0, 0)
	x, y := new(big.Int), new(big.Int)
	addX, addY := new(big.Int).Set(Bx), new(big.Int).Set(By)

	// Process each bit of k from least significant to most significant
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			// Add the current point to the result
			if x.Sign() == 0 && y.Sign() == 0 {
				// First addition, just copy the point
				x.Set(addX)
				y.Set(addY)
			} else {
				// Regular point addition
				x, y = bitCurve.Add(x, y, addX, addY)
			}
		}
		// Double the point for the next bit
		addX, addY = bitCurve.Double(addX, addY)
	}

	return x, y
}
