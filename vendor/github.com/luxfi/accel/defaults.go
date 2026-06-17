//go:build !cgo

// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package accel

// Noop implementations for non-CGO builds.
// These are trivial functions that return immediately, allowing
// the compiler to inline and eliminate calls when callers check for ErrNotSupported.

// DefaultSession returns ErrNoBackends in non-CGO builds.
func DefaultSession() (*Session, error) {
	return nil, ErrNoBackends
}

// closeDefaultSession is a noop in non-CGO builds.
func closeDefaultSession() {}

// MetalAvailable always returns false in non-CGO builds.
func MetalAvailable() bool { return false }

// CUDAAvailable always returns false in non-CGO builds.
func CUDAAvailable() bool { return false }

// WebGPUAvailable always returns false in non-CGO builds.
func WebGPUAvailable() bool { return false }

// BLSBatchVerify returns ErrNotSupported in non-CGO builds.
func BLSBatchVerify(_, _, _ [][]byte) ([]bool, error) {
	return nil, ErrNotSupported
}

// SHA256Batch returns ErrNotSupported in non-CGO builds.
func SHA256Batch(_ [][]byte) ([][]byte, error) {
	return nil, ErrNotSupported
}

// Keccak256Batch returns ErrNotSupported in non-CGO builds.
func Keccak256Batch(_ [][]byte) ([][]byte, error) {
	return nil, ErrNotSupported
}

// MerkleRoot returns ErrNotSupported in non-CGO builds.
func MerkleRoot(_ [][]byte) ([]byte, error) {
	return nil, ErrNotSupported
}

// KyberKeyGen returns ErrNotSupported in non-CGO builds.
func KyberKeyGen() (pk, sk []byte, err error) {
	return nil, nil, ErrNotSupported
}

// KyberEncaps returns ErrNotSupported in non-CGO builds.
func KyberEncaps(_ []byte) (ct, ss []byte, err error) {
	return nil, nil, ErrNotSupported
}

// KyberDecaps returns ErrNotSupported in non-CGO builds.
func KyberDecaps(_, _ []byte) ([]byte, error) {
	return nil, ErrNotSupported
}

// DilithiumSign returns ErrNotSupported in non-CGO builds.
func DilithiumSign(_, _ []byte) ([]byte, error) {
	return nil, ErrNotSupported
}

// DilithiumVerify returns ErrNotSupported in non-CGO builds.
func DilithiumVerify(_, _, _ []byte) (bool, error) {
	return false, ErrNotSupported
}

// NTTForward returns ErrNotSupported in non-CGO builds.
func NTTForward(_, _ []uint64, _ uint64) error {
	return ErrNotSupported
}

// NTTInverse returns ErrNotSupported in non-CGO builds.
func NTTInverse(_, _ []uint64, _ uint64) error {
	return ErrNotSupported
}

// MSM returns ErrNotSupported in non-CGO builds.
func MSM(_, _ [][]byte) ([]byte, error) {
	return nil, ErrNotSupported
}
