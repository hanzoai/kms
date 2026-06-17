// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import "errors"

const (
	SecretKeyLen = 32
	PublicKeyLen = 48 // Compressed G1 point
	SignatureLen = 96 // Compressed G2 point
)

var (
	ErrNoPublicKeys               = errors.New("no public keys")
	ErrFailedPublicKeyDecompress  = errors.New("couldn't decompress public key")
	ErrInvalidPublicKey           = errors.New("invalid public key")
	ErrFailedPublicKeyAggregation = errors.New("couldn't aggregate public keys")
	ErrFailedSignatureDecompress  = errors.New("couldn't decompress signature")
	ErrInvalidSignature           = errors.New("invalid signature")
	ErrNoSignatures               = errors.New("no signatures")
	ErrFailedSignatureAggregation = errors.New("couldn't aggregate signatures")
	ErrFailedSecretKeyDeserialize = errors.New("couldn't deserialize secret key")
	ErrInvalidInput               = errors.New("invalid input")
	ErrGPUNotAvailable            = errors.New("GPU not available")
)
