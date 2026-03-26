// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package crypto

import (
	"errors"

	"github.com/luxfi/crypto/encryption"
)

var hpkeInfo = []byte("hanzo-kms-cek")

// WrapCEK encrypts a CEK to a recipient's HPKE public key using X25519 HPKE (RFC 9180).
// Returns the concatenation of the encapsulated key and ciphertext.
func WrapCEK(cek []byte, recipientPubKey []byte) ([]byte, error) {
	if len(cek) == 0 {
		return nil, errors.New("crypto: cek is empty")
	}
	if len(recipientPubKey) == 0 {
		return nil, errors.New("crypto: recipient public key is empty")
	}
	return encryption.HPKESeal(recipientPubKey, hpkeInfo, cek)
}

// UnwrapCEK decrypts a wrapped CEK using the recipient's HPKE private key.
func UnwrapCEK(wrappedCEK []byte, recipientPrivKey []byte) ([]byte, error) {
	if len(wrappedCEK) == 0 {
		return nil, errors.New("crypto: wrapped cek is empty")
	}
	if len(recipientPrivKey) == 0 {
		return nil, errors.New("crypto: recipient private key is empty")
	}
	kp, err := encryption.HPKEKeyPairFromBytes(recipientPrivKey)
	if err != nil {
		return nil, err
	}
	return encryption.HPKEOpen(kp, hpkeInfo, wrappedCEK)
}

// GenerateHPKEKeyPair generates a new HPKE key pair for CEK wrapping.
// Returns (publicKey, privateKey, error).
func GenerateHPKEKeyPair() (pub []byte, priv []byte, err error) {
	kp, err := encryption.GenerateHPKEKeyPair()
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := kp.PrivateKeyBytes()
	if err != nil {
		return nil, nil, err
	}
	return kp.PublicKeyBytes(), privBytes, nil
}
