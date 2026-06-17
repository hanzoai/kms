// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

type Signer interface {
	PublicKey() *PublicKey
	Sign(msg []byte) (*Signature, error)
	SignProofOfPossession(msg []byte) (*Signature, error)
}
