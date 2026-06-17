// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package localsigner

import (
	"errors"

	"github.com/luxfi/crypto/bls"
)

var (
	ErrFailedSecretKeyDeserialize            = errors.New("couldn't deserialize secret key")
	_                             bls.Signer = (*LocalSigner)(nil)
)

type LocalSigner struct {
	sk *bls.SecretKey
	pk *bls.PublicKey
}

// New generates a new signer with a random secret key.
func New() (*LocalSigner, error) {
	sk, err := bls.NewSecretKey()
	if err != nil {
		return nil, err
	}

	pk := sk.PublicKey()
	return &LocalSigner{sk: sk, pk: pk}, nil
}

// ToBytes returns the big-endian format of the secret key.
func (s *LocalSigner) ToBytes() []byte {
	return bls.SecretKeyToBytes(s.sk)
}

// FromBytes parses the big-endian format of the secret key into a
// secret key.
func FromBytes(skBytes []byte) (*LocalSigner, error) {
	sk, err := bls.SecretKeyFromBytes(skBytes)
	if err != nil {
		return nil, err
	}

	pk := sk.PublicKey()
	return &LocalSigner{sk: sk, pk: pk}, nil
}

// FromSeed derives a signer from seed bytes using proper BLS key derivation.
// This is the preferred way to create a signer from arbitrary seed material
// (like mnemonic-derived bytes) as it handles the key derivation properly.
func FromSeed(seed []byte) (*LocalSigner, error) {
	sk, err := bls.SecretKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}

	pk := sk.PublicKey()
	return &LocalSigner{sk: sk, pk: pk}, nil
}

// PublicKey returns the public key that corresponds to this secret
// key.
func (s *LocalSigner) PublicKey() *bls.PublicKey {
	return s.pk
}

// Sign [msg] to authorize this message
func (s *LocalSigner) Sign(msg []byte) (*bls.Signature, error) {
	return s.sk.Sign(msg)
}

// SignProofOfPossession signs [msg] to prove the ownership
func (s *LocalSigner) SignProofOfPossession(msg []byte) (*bls.Signature, error) {
	return s.sk.SignProofOfPossession(msg)
}
