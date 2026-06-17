// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package bls

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/ecc/bls12381"
	blssign "github.com/cloudflare/circl/sign/bls"
	"github.com/luxfi/crypto/secret"
)

// Domain separation tags - must match the CGO version (blst) exactly
var (
	dstSignature = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	dstPoP       = []byte("BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
)

type (
	SecretKey struct {
		sk *blssign.PrivateKey[blssign.KeyG1SigG2]
	}

	PublicKey struct {
		pk *blssign.PublicKey[blssign.KeyG1SigG2]
	}

	Signature struct {
		sig blssign.Signature
	}

	AggregatePublicKey = PublicKey
	AggregateSignature = Signature
)

func NewSecretKey() (*SecretKey, error) {
	var result *SecretKey
	var keyErr error
	secret.Do(func() {
		ikm := make([]byte, 32)
		rand.Read(ikm)
		defer clear(ikm)

		sk, err := blssign.KeyGen[blssign.KeyG1SigG2](ikm, nil, nil)
		if err != nil {
			keyErr = err
			return
		}
		result = &SecretKey{sk: sk}
	})
	return result, keyErr
}

func SecretKeyToBytes(sk *SecretKey) []byte {
	if sk == nil || sk.sk == nil {
		return nil
	}
	data, _ := sk.sk.MarshalBinary()
	return data
}

// SecretKeyFromSeed derives a secret key from a seed using proper BLS key derivation.
// The seed is passed through internal key derivation, so any 32+ byte input
// will produce a valid secret key.
func SecretKeyFromSeed(seed []byte) (*SecretKey, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	sk, err := blssign.KeyGen[blssign.KeyG1SigG2](seed, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SecretKey{sk: sk}, nil
}

func SecretKeyFromBytes(skBytes []byte) (*SecretKey, error) {
	if len(skBytes) != SecretKeyLen {
		return nil, ErrFailedSecretKeyDeserialize
	}
	var result *SecretKey
	var keyErr error
	secret.Do(func() {
		sk := new(blssign.PrivateKey[blssign.KeyG1SigG2])
		if err := sk.UnmarshalBinary(skBytes); err != nil {
			keyErr = ErrFailedSecretKeyDeserialize
			return
		}
		result = &SecretKey{sk: sk}
	})
	return result, keyErr
}

func (sk *SecretKey) PublicKey() *PublicKey {
	if sk == nil || sk.sk == nil {
		return nil
	}
	return &PublicKey{pk: sk.sk.PublicKey()}
}

func (sk *SecretKey) Sign(msg []byte) (*Signature, error) {
	if sk == nil || sk.sk == nil {
		return nil, errors.New("nil secret key")
	}
	return &Signature{sig: blssign.Sign(sk.sk, msg)}, nil
}

// SignProofOfPossession signs a [msg] to prove the ownership of this secret key.
// Uses the PoP DST (BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_) for domain separation.
// This MUST use a different DST than Sign() to prevent cross-protocol attacks.
func (sk *SecretKey) SignProofOfPossession(msg []byte) (*Signature, error) {
	if sk == nil || sk.sk == nil {
		return nil, errors.New("nil secret key")
	}

	// Get the scalar from the private key
	skBytes, err := sk.sk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Create scalar from private key bytes
	var scalar bls12381.Scalar
	scalar.SetBytes(skBytes)

	// Hash message to G2 with PoP DST
	var sigPoint bls12381.G2
	sigPoint.Hash(msg, dstPoP)

	// Multiply by secret key scalar: sig = sk * H(msg)
	sigPoint.ScalarMult(&scalar, &sigPoint)

	return &Signature{sig: sigPoint.BytesCompressed()}, nil
}

func PublicKeyToCompressedBytes(pk *PublicKey) []byte {
	if pk == nil || pk.pk == nil {
		return nil
	}
	data, _ := pk.pk.MarshalBinary()
	return data
}

func PublicKeyFromCompressedBytes(pkBytes []byte) (*PublicKey, error) {
	pk := new(blssign.PublicKey[blssign.KeyG1SigG2])
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return nil, ErrFailedPublicKeyDecompress
	}
	if !pk.Validate() {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKey{pk: pk}, nil
}

func PublicKeyToUncompressedBytes(key *PublicKey) []byte {
	return PublicKeyToCompressedBytes(key)
}

func PublicKeyFromValidUncompressedBytes(pkBytes []byte) *PublicKey {
	pk := new(blssign.PublicKey[blssign.KeyG1SigG2])
	_ = pk.UnmarshalBinary(pkBytes)
	return &PublicKey{pk: pk}
}

func AggregatePublicKeys(pks []*PublicKey) (*PublicKey, error) {
	if len(pks) == 0 {
		return nil, ErrNoPublicKeys
	}

	var agg bls12381.G1
	agg.SetIdentity()

	for _, pk := range pks {
		if pk == nil || pk.pk == nil {
			return nil, ErrInvalidPublicKey
		}
		pkBytes, err := pk.pk.MarshalBinary()
		if err != nil {
			return nil, ErrFailedPublicKeyAggregation
		}
		var pt bls12381.G1
		if err := pt.SetBytes(pkBytes); err != nil {
			return nil, ErrFailedPublicKeyAggregation
		}
		agg.Add(&agg, &pt)
	}

	result := new(blssign.PublicKey[blssign.KeyG1SigG2])
	if err := result.UnmarshalBinary(agg.BytesCompressed()); err != nil {
		return nil, ErrFailedPublicKeyAggregation
	}
	return &PublicKey{pk: result}, nil
}

// isIdentityG1 checks if a public key is the identity point (point at infinity).
// Returns true if the key is the identity, false otherwise.
func isIdentityG1(pk *blssign.PublicKey[blssign.KeyG1SigG2]) bool {
	// Serialize the public key and check if it's all zeros (compressed identity)
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return false
	}
	// BLS12-381 G1 compressed identity point is a specific encoding
	// Check if it matches the identity point encoding
	for _, b := range pkBytes {
		if b != 0 {
			return false
		}
	}
	return true
}

func Verify(pk *PublicKey, sig *Signature, msg []byte) bool {
	if pk == nil || pk.pk == nil || sig == nil {
		return false
	}
	// Check that public key is not the identity point (zero-key)
	// Identity point verification would trivially pass for any signature
	if isIdentityG1(pk.pk) {
		return false
	}
	return blssign.Verify(pk.pk, msg, sig.sig)
}

// VerifyProofOfPossession verifies the possession of the secret pre-image of [pk].
// Uses the PoP DST (BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_) for domain separation.
func VerifyProofOfPossession(pk *PublicKey, sig *Signature, msg []byte) bool {
	if pk == nil || pk.pk == nil || sig == nil {
		return false
	}
	// Check that public key is not the identity point (zero-key)
	if isIdentityG1(pk.pk) {
		return false
	}

	// Parse the signature as a G2 point
	var sigPoint bls12381.G2
	if err := sigPoint.SetBytes(sig.sig); err != nil {
		return false
	}

	// Get the public key as a G1 point
	pkBytes, err := pk.pk.MarshalBinary()
	if err != nil {
		return false
	}
	var pkPoint bls12381.G1
	if err := pkPoint.SetBytes(pkBytes); err != nil {
		return false
	}

	// Hash message to G2 with PoP DST
	var hashPoint bls12381.G2
	hashPoint.Hash(msg, dstPoP)

	// BLS verification: e(pk, H(msg)) == e(G1, sig)
	// This is equivalent to: e(pk, H(msg)) * e(-G1, sig) == 1
	// Or: e(pk, H(msg)) == e(G1, sig)

	// Verify using pairing check: e(G1, sig) == e(pk, H(msg))
	// Which is: e(-G1, sig) * e(pk, H(msg)) == 1
	// Copy the generator bytes then negate
	var negG1 bls12381.G1
	_ = negG1.SetBytes(bls12381.G1Generator().BytesCompressed())
	negG1.Neg()

	// Prepare points for pairing
	listG1 := []*bls12381.G1{&negG1, &pkPoint}
	listG2 := []*bls12381.G2{&sigPoint, &hashPoint}

	// ProdPairFrac computes the product of pairings and checks if result equals identity
	result := bls12381.ProdPairFrac(listG1, listG2, []int{1, 1})
	return result.IsIdentity()
}

func SignatureToBytes(sig *Signature) []byte {
	if sig == nil {
		return nil
	}
	return sig.sig
}

func SignatureFromBytes(sigBytes []byte) (*Signature, error) {
	if len(sigBytes) != SignatureLen {
		return nil, ErrFailedSignatureDecompress
	}
	for _, b := range sigBytes {
		if b != 0 {
			return &Signature{sig: sigBytes}, nil
		}
	}
	return nil, ErrFailedSignatureDecompress
}

func AggregateSignatures(sigs []*Signature) (*Signature, error) {
	if len(sigs) == 0 {
		return nil, ErrNoSignatures
	}

	sigBytes := make([]blssign.Signature, len(sigs))
	for i, sig := range sigs {
		if sig == nil {
			return nil, ErrFailedSignatureAggregation
		}
		sigBytes[i] = sig.sig
	}

	aggSig, err := blssign.Aggregate[blssign.KeyG1SigG2](blssign.KeyG1SigG2{}, sigBytes)
	if err != nil {
		return nil, ErrFailedSignatureAggregation
	}
	return &Signature{sig: aggSig}, nil
}
