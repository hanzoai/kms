// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package bls

import (
	"crypto/rand"
	"errors"

	"github.com/luxfi/crypto/secret"
	blst "github.com/supranational/blst/bindings/go"
)

// Domain separation tags
var (
	dstSignature = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	dstPoP       = []byte("BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
)

// Types wrapping the blst BLS types
type (
	SecretKey struct {
		sk *blst.SecretKey
	}

	PublicKey struct {
		pk *blst.P1Affine
	}

	Signature struct {
		sig *blst.P2Affine
	}

	AggregatePublicKey = PublicKey
	AggregateSignature = Signature
)

// NewSecretKey generates a new secret key from the local source of
// cryptographically secure randomness.
func NewSecretKey() (*SecretKey, error) {
	var result *SecretKey
	secret.Do(func() {
		ikm := make([]byte, 32)
		rand.Read(ikm)
		defer clear(ikm)
		result = &SecretKey{sk: blst.KeyGen(ikm)}
	})
	return result, nil
}

// SecretKeyToBytes returns the big-endian format of the secret key.
func SecretKeyToBytes(sk *SecretKey) []byte {
	if sk == nil || sk.sk == nil {
		return nil
	}
	return sk.sk.Serialize()
}

// SecretKeyFromSeed derives a secret key from a seed using proper BLS key derivation.
// The seed is passed through HKDF internally by blst.KeyGen, so any 32+ byte input
// will produce a valid secret key.
func SecretKeyFromSeed(seed []byte) (*SecretKey, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	sk := blst.KeyGen(seed)
	return &SecretKey{sk: sk}, nil
}

// SecretKeyFromBytes parses the big-endian format of the secret key into a
// secret key.
func SecretKeyFromBytes(skBytes []byte) (*SecretKey, error) {
	if len(skBytes) != SecretKeyLen {
		return nil, ErrFailedSecretKeyDeserialize
	}
	// Reject zero secret key (security: not a valid scalar)
	allZero := true
	for _, b := range skBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, ErrFailedSecretKeyDeserialize
	}
	var result *SecretKey
	secret.Do(func() {
		sk := new(blst.SecretKey)
		sk.Deserialize(skBytes)
		result = &SecretKey{sk: sk}
	})
	return result, nil
}

// PublicKey returns the public key associated with the secret key.
func (sk *SecretKey) PublicKey() *PublicKey {
	if sk == nil || sk.sk == nil {
		return nil
	}
	pk := new(blst.P1Affine)
	pk.From(sk.sk)
	return &PublicKey{pk: pk}
}

// Sign [msg] to authorize that this private key signed [msg].
func (sk *SecretKey) Sign(msg []byte) (*Signature, error) {
	if sk == nil || sk.sk == nil {
		return nil, errors.New("nil secret key")
	}
	sig := new(blst.P2Affine)
	sig.Sign(sk.sk, msg, dstSignature)
	return &Signature{sig: sig}, nil
}

// SignProofOfPossession signs a [msg] to prove the ownership of this secret key.
func (sk *SecretKey) SignProofOfPossession(msg []byte) (*Signature, error) {
	if sk == nil || sk.sk == nil {
		return nil, errors.New("nil secret key")
	}
	sig := new(blst.P2Affine)
	sig.Sign(sk.sk, msg, dstPoP)
	return &Signature{sig: sig}, nil
}

// PublicKeyToCompressedBytes returns the compressed big-endian format of the
// public key.
func PublicKeyToCompressedBytes(pk *PublicKey) []byte {
	if pk == nil || pk.pk == nil {
		return nil
	}
	return pk.pk.Compress()
}

// PublicKeyFromCompressedBytes parses the compressed big-endian format of the
// public key into a public key.
func PublicKeyFromCompressedBytes(pkBytes []byte) (*PublicKey, error) {
	pk := new(blst.P1Affine)
	pk = pk.Uncompress(pkBytes)
	if pk == nil {
		return nil, ErrFailedPublicKeyDecompress
	}
	if !pk.KeyValidate() {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKey{pk: pk}, nil
}

// PublicKeyToUncompressedBytes returns the uncompressed big-endian format of
// the public key.
func PublicKeyToUncompressedBytes(key *PublicKey) []byte {
	if key == nil || key.pk == nil {
		return nil
	}
	return key.pk.Serialize()
}

// PublicKeyFromValidUncompressedBytes parses the uncompressed big-endian format
// of the public key into a public key. It is assumed that the provided bytes
// are valid.
func PublicKeyFromValidUncompressedBytes(pkBytes []byte) *PublicKey {
	pk := new(blst.P1Affine)
	pk.Deserialize(pkBytes)
	return &PublicKey{pk: pk}
}

// AggregatePublicKeys aggregates a non-zero number of public keys into a single
// aggregated public key.
func AggregatePublicKeys(pks []*PublicKey) (*PublicKey, error) {
	if len(pks) == 0 {
		return nil, ErrNoPublicKeys
	}

	agg := new(blst.P1Aggregate)
	for _, pk := range pks {
		if pk == nil || pk.pk == nil {
			return nil, ErrInvalidPublicKey
		}
		if !agg.Add(pk.pk, true) {
			return nil, ErrFailedPublicKeyAggregation
		}
	}

	return &PublicKey{pk: agg.ToAffine()}, nil
}

// isIdentityG1 checks if a public key is the identity point (point at infinity).
// Returns true if the key is the identity, false otherwise.
func isIdentityG1(pk *blst.P1Affine) bool {
	// Check if the point is at infinity using blst's built-in check
	// The identity point in G1 is represented as all zeros in compressed form
	pkBytes := pk.Compress()
	// Check for all-zero bytes (identity point encoding)
	for _, b := range pkBytes {
		if b != 0 {
			return false
		}
	}
	return true
}

// Verify the [sig] of [msg] against the [pk].
func Verify(pk *PublicKey, sig *Signature, msg []byte) bool {
	if pk == nil || pk.pk == nil || sig == nil || sig.sig == nil {
		return false
	}
	// Check that public key is not the identity point (zero-key)
	// Identity point verification would trivially pass for any signature
	if isIdentityG1(pk.pk) {
		return false
	}
	return sig.sig.Verify(true, pk.pk, false, msg, dstSignature)
}

// VerifyProofOfPossession verifies the possession of the secret pre-image of [sk]
func VerifyProofOfPossession(pk *PublicKey, sig *Signature, msg []byte) bool {
	if pk == nil || pk.pk == nil || sig == nil || sig.sig == nil {
		return false
	}
	// Check that public key is not the identity point (zero-key)
	if isIdentityG1(pk.pk) {
		return false
	}
	return sig.sig.Verify(true, pk.pk, false, msg, dstPoP)
}

// SignatureToBytes returns the compressed big-endian format of the signature.
func SignatureToBytes(sig *Signature) []byte {
	if sig == nil || sig.sig == nil {
		return nil
	}
	return sig.sig.Compress()
}

// SignatureFromBytes parses the compressed big-endian format of the signature
// into a signature.
func SignatureFromBytes(sigBytes []byte) (*Signature, error) {
	if len(sigBytes) != SignatureLen {
		return nil, ErrFailedSignatureDecompress
	}

	sig := new(blst.P2Affine)
	sig = sig.Uncompress(sigBytes)
	if sig == nil {
		return nil, ErrFailedSignatureDecompress
	}

	if !sig.SigValidate(false) {
		return nil, ErrInvalidSignature
	}

	return &Signature{sig: sig}, nil
}

// AggregateSignatures aggregates a non-zero number of signatures into a single
// aggregated signature.
func AggregateSignatures(sigs []*Signature) (*Signature, error) {
	if len(sigs) == 0 {
		return nil, ErrNoSignatures
	}

	agg := new(blst.P2Aggregate)
	for _, sig := range sigs {
		if sig == nil || sig.sig == nil {
			return nil, ErrFailedSignatureAggregation
		}
		if !agg.Add(sig.sig, true) {
			return nil, ErrFailedSignatureAggregation
		}
	}

	return &Signature{sig: agg.ToAffine()}, nil
}
