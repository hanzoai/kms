// Package common provides shared utilities for post-quantum crypto implementations
package common

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// HashFunc represents available hash functions
type HashFunc int

const (
	SHA256Hash HashFunc = iota
	SHA512Hash
	SHA3_256Hash
	SHA3_512Hash
)

// GetHasher returns a hash function instance
func GetHasher(h HashFunc) hash.Hash {
	switch h {
	case SHA512Hash:
		return sha512.New()
	default:
		return sha256.New()
	}
}

// DeriveKey derives deterministic key material from seed
func DeriveKey(seed []byte, label string, outputLen int) []byte {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte(label))
	baseHash := h.Sum(nil)

	output := make([]byte, outputLen)
	for i := 0; i < outputLen; i += len(baseHash) {
		h.Reset()
		h.Write(baseHash)
		h.Write([]byte{byte(i / len(baseHash))})
		chunk := h.Sum(nil)

		end := i + len(baseHash)
		if end > outputLen {
			end = outputLen
		}
		copy(output[i:end], chunk)
		baseHash = chunk
	}

	return output
}

// XOF extends output using a hash function as XOF
func XOF(seed []byte, outputLen int) []byte {
	output := make([]byte, outputLen)
	h := sha256.New()
	h.Write(seed)
	hash := h.Sum(nil)

	for i := 0; i < outputLen; i += len(hash) {
		end := i + len(hash)
		if end > outputLen {
			end = outputLen
		}
		copy(output[i:end], hash)
		if end < outputLen {
			h.Reset()
			h.Write(hash)
			hash = h.Sum(nil)
		}
	}

	return output
}

// SecureCompare performs constant-time comparison
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// ClearBytes securely clears sensitive data
func ClearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
