// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

// Compatibility functions to support legacy API

// PublicFromSecretKey returns the public key associated with sk
func PublicFromSecretKey(sk *SecretKey) *PublicKey {
	if sk == nil {
		return nil
	}
	return sk.PublicKey()
}

// SignProofOfPossession signs msg to prove ownership of sk
func SignProofOfPossession(sk *SecretKey, msg []byte) *Signature {
	if sk == nil {
		return nil
	}
	sig, _ := sk.SignProofOfPossession(msg)
	return sig
}
