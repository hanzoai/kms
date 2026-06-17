// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mldsa implements ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
// using Cloudflare's circl library with automatic CGO optimizations when available.
package mldsa

import (
	"crypto"
	"errors"
	"io"
	"runtime"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Mode represents different security levels of ML-DSA
type Mode int

const (
	// MLDSA44 provides 128-bit security (NIST Level 2)
	MLDSA44 Mode = iota
	// MLDSA65 provides 192-bit security (NIST Level 3)
	MLDSA65
	// MLDSA87 provides 256-bit security (NIST Level 5)
	MLDSA87
)

// Size constants for each mode
const (
	MLDSA44PublicKeySize  = mldsa44.PublicKeySize
	MLDSA44PrivateKeySize = mldsa44.PrivateKeySize
	MLDSA44SignatureSize  = mldsa44.SignatureSize

	MLDSA65PublicKeySize  = mldsa65.PublicKeySize
	MLDSA65PrivateKeySize = mldsa65.PrivateKeySize
	MLDSA65SignatureSize  = mldsa65.SignatureSize

	MLDSA87PublicKeySize  = mldsa87.PublicKeySize
	MLDSA87PrivateKeySize = mldsa87.PrivateKeySize
	MLDSA87SignatureSize  = mldsa87.SignatureSize
)

var (
	ErrInvalidMode      = errors.New("invalid ML-DSA mode")
	ErrInvalidKeySize   = errors.New("invalid key size")
	ErrInvalidSignature = errors.New("invalid signature")
)

// PrivateKey represents an ML-DSA private key
type PrivateKey struct {
	mode      Mode
	secretKey []byte
	PublicKey *PublicKey
}

// PublicKey represents an ML-DSA public key
type PublicKey struct {
	mode      Mode
	publicKey []byte
}

// GetPublicKeySize returns the size of a public key for the given mode
func GetPublicKeySize(mode Mode) int {
	switch mode {
	case MLDSA44:
		return MLDSA44PublicKeySize
	case MLDSA65:
		return MLDSA65PublicKeySize
	case MLDSA87:
		return MLDSA87PublicKeySize
	default:
		return 0
	}
}

// GetSignatureSize returns the size of a signature for the given mode
func GetSignatureSize(mode Mode) int {
	switch mode {
	case MLDSA44:
		return MLDSA44SignatureSize
	case MLDSA65:
		return MLDSA65SignatureSize
	case MLDSA87:
		return MLDSA87SignatureSize
	default:
		return 0
	}
}

// GenerateKey generates a new ML-DSA key pair using circl
func GenerateKey(rand io.Reader, mode Mode) (*PrivateKey, error) {
	var pubBytes, privBytes []byte

	switch mode {
	case MLDSA44:
		pub, priv, err := mldsa44.GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		pubBytes, err = pub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		privBytes, err = priv.MarshalBinary()
		if err != nil {
			return nil, err
		}

	case MLDSA65:
		pub, priv, err := mldsa65.GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		pubBytes, err = pub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		privBytes, err = priv.MarshalBinary()
		if err != nil {
			return nil, err
		}

	case MLDSA87:
		pub, priv, err := mldsa87.GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		pubBytes, err = pub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		privBytes, err = priv.MarshalBinary()
		if err != nil {
			return nil, err
		}

	default:
		return nil, ErrInvalidMode
	}

	priv := &PrivateKey{
		mode:      mode,
		secretKey: privBytes,
		PublicKey: &PublicKey{
			mode:      mode,
			publicKey: pubBytes,
		},
	}
	runtime.SetFinalizer(priv, (*PrivateKey).Zeroize)
	return priv, nil
}

// Sign signs a message with the private key using circl.
// Uses nil context -- callers requiring domain separation should use SignCtx.
func (priv *PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.SignCtx(rand, message, nil)
}

// SignCtx signs a message with domain-separating context.
// FIPS 204 Section 5.2: ctx is an optional octet string (0-255 bytes) bound
// into the signature. Callers SHOULD use a non-nil context to prevent
// cross-protocol signature replay.
func (priv *PrivateKey) SignCtx(rand io.Reader, message, ctx []byte) ([]byte, error) {
	switch priv.mode {
	case MLDSA44:
		var sk mldsa44.PrivateKey
		if err := (&sk).UnmarshalBinary(priv.secretKey); err != nil {
			return nil, err
		}
		sig := make([]byte, MLDSA44SignatureSize)
		if err := mldsa44.SignTo(&sk, message, ctx, true, sig); err != nil {
			return nil, err
		}
		return sig, nil

	case MLDSA65:
		var sk mldsa65.PrivateKey
		if err := (&sk).UnmarshalBinary(priv.secretKey); err != nil {
			return nil, err
		}
		sig := make([]byte, MLDSA65SignatureSize)
		if err := mldsa65.SignTo(&sk, message, ctx, true, sig); err != nil {
			return nil, err
		}
		return sig, nil

	case MLDSA87:
		var sk mldsa87.PrivateKey
		if err := (&sk).UnmarshalBinary(priv.secretKey); err != nil {
			return nil, err
		}
		sig := make([]byte, MLDSA87SignatureSize)
		if err := mldsa87.SignTo(&sk, message, ctx, true, sig); err != nil {
			return nil, err
		}
		return sig, nil

	default:
		return nil, ErrInvalidMode
	}
}

// Verify verifies a signature with the public key using circl
// The opts parameter is ignored but kept for crypto.Signer interface compatibility
func (pub *PublicKey) Verify(message, signature []byte, opts crypto.SignerOpts) bool {
	return pub.VerifySignature(message, signature)
}

// VerifySignature verifies a signature with the public key (simplified API).
// Uses nil context -- callers requiring domain separation should use VerifySignatureCtx.
func (pub *PublicKey) VerifySignature(message, signature []byte) bool {
	return pub.VerifySignatureCtx(message, signature, nil)
}

// VerifySignatureCtx verifies a signature with domain-separating context.
// FIPS 204 Section 5.3: ctx is an optional octet string (0-255 bytes) bound
// into the signature. Callers SHOULD use a non-nil context to prevent
// cross-protocol signature replay.
func (pub *PublicKey) VerifySignatureCtx(message, signature, ctx []byte) bool {
	switch pub.mode {
	case MLDSA44:
		var pk mldsa44.PublicKey
		if err := (&pk).UnmarshalBinary(pub.publicKey); err != nil {
			return false
		}
		return mldsa44.Verify(&pk, message, ctx, signature)

	case MLDSA65:
		var pk mldsa65.PublicKey
		if err := (&pk).UnmarshalBinary(pub.publicKey); err != nil {
			return false
		}
		return mldsa65.Verify(&pk, message, ctx, signature)

	case MLDSA87:
		var pk mldsa87.PublicKey
		if err := (&pk).UnmarshalBinary(pub.publicKey); err != nil {
			return false
		}
		return mldsa87.Verify(&pk, message, ctx, signature)

	default:
		return false
	}
}

// Public returns the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return priv.PublicKey
}

// Bytes returns the serialized private key
func (priv *PrivateKey) Bytes() []byte {
	return priv.secretKey
}

// Zeroize overwrites the private key material with zeros.
// Best-effort: the Go runtime may have copied the bytes elsewhere.
// A GC finalizer calls this automatically when the key becomes unreachable,
// but callers should call it explicitly when the key is no longer needed
// for more predictable cleanup.
func (priv *PrivateKey) Zeroize() {
	for i := range priv.secretKey {
		priv.secretKey[i] = 0
	}
}

// Bytes returns the serialized public key
func (pub *PublicKey) Bytes() []byte {
	return pub.publicKey
}

// PrivateKeyFromBytes deserializes a private key
func PrivateKeyFromBytes(mode Mode, data []byte) (*PrivateKey, error) {
	expectedSize := 0
	switch mode {
	case MLDSA44:
		expectedSize = MLDSA44PrivateKeySize
	case MLDSA65:
		expectedSize = MLDSA65PrivateKeySize
	case MLDSA87:
		expectedSize = MLDSA87PrivateKeySize
	default:
		return nil, ErrInvalidMode
	}

	if len(data) != expectedSize {
		return nil, ErrInvalidKeySize
	}

	// Extract public key from private key
	var pubBytes []byte
	var err error

	switch mode {
	case MLDSA44:
		var sk mldsa44.PrivateKey
		if err := (&sk).UnmarshalBinary(data); err != nil {
			return nil, err
		}
		pk := sk.Public().(*mldsa44.PublicKey)
		pubBytes, err = pk.MarshalBinary()
		if err != nil {
			return nil, err
		}

	case MLDSA65:
		var sk mldsa65.PrivateKey
		if err := (&sk).UnmarshalBinary(data); err != nil {
			return nil, err
		}
		pk := sk.Public().(*mldsa65.PublicKey)
		pubBytes, err = pk.MarshalBinary()
		if err != nil {
			return nil, err
		}

	case MLDSA87:
		var sk mldsa87.PrivateKey
		if err := (&sk).UnmarshalBinary(data); err != nil {
			return nil, err
		}
		pk := sk.Public().(*mldsa87.PublicKey)
		pubBytes, err = pk.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}

	priv := &PrivateKey{
		mode:      mode,
		secretKey: data,
		PublicKey: &PublicKey{
			mode:      mode,
			publicKey: pubBytes,
		},
	}
	runtime.SetFinalizer(priv, (*PrivateKey).Zeroize)
	return priv, nil
}

// PublicKeyFromBytes deserializes a public key
func PublicKeyFromBytes(data []byte, mode Mode) (*PublicKey, error) {
	expectedSize := GetPublicKeySize(mode)
	if expectedSize == 0 {
		return nil, ErrInvalidMode
	}
	if len(data) != expectedSize {
		return nil, ErrInvalidKeySize
	}

	// Validate by trying to unmarshal
	switch mode {
	case MLDSA44:
		var pk mldsa44.PublicKey
		if err := (&pk).UnmarshalBinary(data); err != nil {
			return nil, err
		}
	case MLDSA65:
		var pk mldsa65.PublicKey
		if err := (&pk).UnmarshalBinary(data); err != nil {
			return nil, err
		}
	case MLDSA87:
		var pk mldsa87.PublicKey
		if err := (&pk).UnmarshalBinary(data); err != nil {
			return nil, err
		}
	}

	return &PublicKey{
		mode:      mode,
		publicKey: data,
	}, nil
}
