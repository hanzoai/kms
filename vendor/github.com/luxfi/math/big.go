// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package math re-exports big.Int utilities for backwards compatibility.
// New code should import github.com/luxfi/math/big directly.
package math

import (
	"math/big"

	luxbig "github.com/luxfi/math/big"
)

// Type aliases for backwards compatibility.
type (
	HexOrDecimal256 = luxbig.HexOrDecimal256
	Decimal256      = luxbig.Decimal256
	HexOrDecimal64  = luxbig.HexOrDecimal64
)

// Function aliases for backwards compatibility.
var (
	NewHexOrDecimal256 = luxbig.NewHexOrDecimal256
	NewDecimal256      = luxbig.NewDecimal256
	ParseBig256        = luxbig.ParseBig256
	MustParseBig256    = luxbig.MustParseBig256
	ParseUint64        = luxbig.ParseUint64
	MustParseUint64    = luxbig.MustParseUint64
	BigPow             = luxbig.BigPow
	BigMax             = luxbig.BigMax
	BigMin             = luxbig.BigMin
	PaddedBigBytes     = luxbig.PaddedBigBytes
	ReadBits           = luxbig.ReadBits
	U256               = luxbig.U256
	U256Bytes          = luxbig.U256Bytes
)

// MaxBig256 is the maximum value for a 256-bit unsigned integer.
var MaxBig256 = new(big.Int).Set(luxbig.MaxBig256)
