// Package common provides shared utilities for post-quantum crypto implementations
package common

import (
	"errors"
	"io"
)

// ValidateMode checks if a mode value is within valid range
func ValidateMode(mode int, min, max int) error {
	if mode < min || mode > max {
		return errors.New("invalid mode")
	}
	return nil
}

// ValidateRandomSource checks if random source is not nil
func ValidateRandomSource(rand io.Reader) error {
	if rand == nil {
		return errors.New("random source is nil")
	}
	return nil
}

// GenerateRandomBytes generates random bytes with validation
func GenerateRandomBytes(rand io.Reader, size int) ([]byte, error) {
	if err := ValidateRandomSource(rand); err != nil {
		return nil, err
	}

	bytes := make([]byte, size)
	if _, err := io.ReadFull(rand, bytes); err != nil {
		return nil, err
	}

	return bytes, nil
}

// AllocateCombined allocates a single buffer for multiple data segments
func AllocateCombined(sizes ...int) []byte {
	total := 0
	for _, size := range sizes {
		total += size
	}
	return make([]byte, total)
}

// SplitBuffer splits a buffer into segments of specified sizes
func SplitBuffer(buffer []byte, sizes ...int) [][]byte {
	segments := make([][]byte, len(sizes))
	offset := 0

	for i, size := range sizes {
		if offset+size > len(buffer) {
			panic("buffer too small for requested segments")
		}
		segments[i] = buffer[offset : offset+size]
		offset += size
	}

	return segments
}

// CopyWithPadding copies source to destination with padding if needed
func CopyWithPadding(dst, src []byte, padValue byte) {
	copy(dst, src)
	if len(src) < len(dst) {
		for i := len(src); i < len(dst); i++ {
			dst[i] = padValue
		}
	}
}

// ConstantTimeSelect returns a if v == 1, b if v == 0
func ConstantTimeSelect(v int, a, b []byte) []byte {
	if len(a) != len(b) {
		panic("slices must have equal length")
	}

	result := make([]byte, len(a))
	for i := range result {
		result[i] = byte(v)*a[i] + byte(1-v)*b[i]
	}
	return result
}

// ValidateBufferSize checks if buffer has expected size
func ValidateBufferSize(buf []byte, expectedSize int, name string) error {
	if len(buf) != expectedSize {
		return errors.New(name + " has invalid size")
	}
	return nil
}

// SafeCopy performs bounds-checked copy
func SafeCopy(dst, src []byte) error {
	if len(dst) < len(src) {
		return errors.New("destination buffer too small")
	}
	copy(dst, src)
	return nil
}

// GenerateDeterministicBytes generates deterministic bytes from seed
func GenerateDeterministicBytes(seed []byte, length int) []byte {
	return DeriveKey(seed, "deterministic", length)
}

// CreateSignatureBuffer creates a signature buffer with proper initialization
func CreateSignatureBuffer(size int) []byte {
	return make([]byte, size)
}

// FillRandomBytes fills existing buffer with random bytes
func FillRandomBytes(rand io.Reader, buf []byte) error {
	if err := ValidateRandomSource(rand); err != nil {
		return err
	}

	_, err := io.ReadFull(rand, buf)
	return err
}

// Min returns the minimum of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max returns the maximum of two integers
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
