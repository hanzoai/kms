// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

// Helper functions to maintain compatibility with node/utils/crypto/bls

// Sign signs a message with a secret key
func Sign(sk *SecretKey, msg []byte) *Signature {
	if sk == nil {
		return nil
	}
	sig, _ := sk.Sign(msg)
	return sig
}

// PublicKeyBytes is a helper that returns the compressed bytes of a public key
func PublicKeyBytes(pk *PublicKey) []byte {
	return PublicKeyToCompressedBytes(pk)
}

// AggregatePublicKeyFromBytes converts bytes to an aggregate public key
func AggregatePublicKeyFromBytes(pkBytes []byte) (*AggregatePublicKey, error) {
	return PublicKeyFromCompressedBytes(pkBytes)
}

// AggregatePublicKeyToBytes converts an aggregate public key to bytes
func AggregatePublicKeyToBytes(apk *AggregatePublicKey) []byte {
	return PublicKeyToCompressedBytes(apk)
}

// AggregateSignatureFromBytes converts bytes to an aggregate signature
func AggregateSignatureFromBytes(sigBytes []byte) (*AggregateSignature, error) {
	return SignatureFromBytes(sigBytes)
}

// AggregateSignatureToBytes converts an aggregate signature to bytes
func AggregateSignatureToBytes(asig *AggregateSignature) []byte {
	return SignatureToBytes(asig)
}

// VerifyAggregate verifies an aggregate signature
func VerifyAggregate(apk *AggregatePublicKey, asig *AggregateSignature, msg []byte) bool {
	return Verify(apk, asig, msg)
}

// VerifyAggregateProofOfPossession verifies an aggregate proof of possession
func VerifyAggregateProofOfPossession(apk *AggregatePublicKey, asig *AggregateSignature, msg []byte) bool {
	return VerifyProofOfPossession(apk, asig, msg)
}
