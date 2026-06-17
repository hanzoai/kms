// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ids

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/luxfi/codec/wrappers"
	"github.com/luxfi/crypto/cb58"
	"github.com/luxfi/crypto/hash"
	"github.com/mr-tron/base58/base58"
)

// Sortable is the interface for types that can be compared for ordering.
type Sortable[T any] interface {
	Compare(T) int
}

const (
	IDLen   = 32
	nullStr = "null"
)

var (
	// Empty is a useful all zero value
	Empty = ID{}

	errMissingQuotes = errors.New("first and last characters should be quotes")

	_ Sortable[ID] = ID{}
)

// ID wraps a 32 byte hash used as an identifier
type ID [IDLen]byte

// ToID attempt to convert a byte slice into an id
func ToID(bytes []byte) (ID, error) {
	return hash.ToHash256(bytes)
}

// FromString is the inverse of ID.String()
func FromString(idStr string) (ID, error) {
	// Check if this is a well-known native chain string
	if id, ok := NativeChainFromString(idStr); ok {
		return id, nil
	}

	bytes, err := cb58.Decode(idStr)
	if err != nil {
		return ID{}, err
	}
	return ToID(bytes)
}

// FromStringWithForce is like FromString but can force ignore checksum errors
func FromStringWithForce(idStr string, forceIgnoreChecksum bool) (ID, error) {
	// Check if this is a well-known native chain string
	if id, ok := NativeChainFromString(idStr); ok {
		return id, nil
	}

	bytes, err := cb58.Decode(idStr)
	if err != nil {
		// If force flag is set and it's a checksum error, try raw base58 decode
		if forceIgnoreChecksum && err == cb58.ErrBadChecksum {
			// Decode raw base58 and take first 32 bytes
			rawBytes, decodeErr := base58.Decode(idStr)
			if decodeErr == nil && len(rawBytes) >= IDLen {
				var id ID
				copy(id[:], rawBytes[:IDLen])
				return id, nil
			}
		}
		return ID{}, err
	}
	return ToID(bytes)
}

// FromStringOrPanic is the same as FromString, but will panic on error
func FromStringOrPanic(idStr string) ID {
	id, err := FromString(idStr)
	if err != nil {
		panic(err)
	}
	return id
}

func (id ID) MarshalJSON() ([]byte, error) {
	// Check if this is a well-known native chain ID
	if nativeStr := NativeChainString(id); nativeStr != "" {
		return []byte(`"` + nativeStr + `"`), nil
	}

	str, err := cb58.Encode(id[:])
	if err != nil {
		return nil, err
	}
	return []byte(`"` + str + `"`), nil
}

func (id *ID) UnmarshalJSON(b []byte) error {
	str := string(b)
	if str == nullStr { // If "null", do nothing
		return nil
	} else if len(str) < 2 {
		return errMissingQuotes
	}

	lastIndex := len(str) - 1
	if str[0] != '"' || str[lastIndex] != '"' {
		return errMissingQuotes
	}

	// Handle empty string - treat as zero ID
	innerStr := str[1:lastIndex]
	if innerStr == "" {
		*id = Empty
		return nil
	}

	// Check if this is a well-known native chain string
	if nativeID, ok := NativeChainFromString(innerStr); ok {
		*id = nativeID
		return nil
	}

	// Parse CB58 formatted string to bytes
	bytes, err := cb58.Decode(innerStr)
	if err != nil {
		return fmt.Errorf("couldn't decode ID to bytes: %w", err)
	}
	*id, err = ToID(bytes)
	return err
}

func (id *ID) UnmarshalText(text []byte) error {
	return id.UnmarshalJSON(text)
}

// Prefix this id to create a more selective id. This can be used to store
// multiple values under the same key. For example:
// prefix1(id) -> confidence
// prefix2(id) -> vertex
// This will return a new id and not modify the original id.
func (id ID) Prefix(prefixes ...uint64) ID {
	packer := wrappers.Packer{
		Bytes: make([]byte, len(prefixes)*wrappers.LongLen+IDLen),
	}

	for _, prefix := range prefixes {
		packer.PackLong(prefix)
	}
	packer.PackFixedBytes(id[:])

	return hash.ComputeHash256Array(packer.Bytes)
}

// Append this id with the provided suffixes and re-hash the result. This
// returns a new ID and does not modify the original ID.
//
// This is used to generate LP-77 validationIDs.
//
// Ref: https://github.com/luxfi/LPs/tree/e333b335c34c8692d84259d21bd07b2bb849dc2c/LPs/77-reinventing-subnets#convertsubnettol1tx
func (id ID) Append(suffixes ...uint32) ID {
	packer := wrappers.Packer{
		Bytes: make([]byte, IDLen+len(suffixes)*wrappers.IntLen),
	}

	packer.PackFixedBytes(id[:])
	for _, suffix := range suffixes {
		packer.PackInt(suffix)
	}

	return hash.ComputeHash256Array(packer.Bytes)
}

// XOR this id and the provided id and return the resulting id.
//
// Note: this id is not modified.
func (id ID) XOR(other ID) ID {
	for i, b := range other {
		id[i] ^= b
	}
	return id
}

// Bit returns the bit value at the ith index of the byte array. Returns 0 or 1
func (id ID) Bit(i uint) int {
	byteIndex := i / BitsPerByte
	bitIndex := i % BitsPerByte

	b := id[byteIndex]

	// b = [7, 6, 5, 4, 3, 2, 1, 0]

	b >>= bitIndex

	// b = [0, ..., bitIndex + 1, bitIndex]
	// 1 = [0, 0, 0, 0, 0, 0, 0, 1]

	b &= 1

	// b = [0, 0, 0, 0, 0, 0, 0, bitIndex]

	return int(b)
}

// Hex returns a hex encoded string of this id.
func (id ID) Hex() string {
	return hex.EncodeToString(id[:])
}

// ToShortID converts this ID to a ShortID by taking the first 20 bytes
func (id ID) ToShortID() ShortID {
	var shortID ShortID
	copy(shortID[:], id[:ShortIDLen])
	return shortID
}

func (id ID) String() string {
	// Check if this is a well-known native chain ID
	if nativeStr := NativeChainString(id); nativeStr != "" {
		return nativeStr
	}

	// We assume that the maximum size of a byte slice that
	// can be stringified is at least the length of an ID
	s, _ := cb58.Encode(id[:])
	return s
}

func (id ID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

func (id ID) Compare(other ID) int {
	return bytes.Compare(id[:], other[:])
}

// IsZero returns true if the ID is all zeros
func (id ID) IsZero() bool {
	return id == Empty
}

// GenerateNodeIDFromBytes generates a node ID from bytes
func GenerateNodeIDFromBytes(bytes []byte) ID {
	return hash.ComputeHash256Array(bytes)
}

// Checksum256 computes SHA256 checksum and returns an ID
func Checksum256(data []byte) ID {
	return hash.ComputeHash256Array(data)
}
