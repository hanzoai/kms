// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

// Package crypto provides key derivation, wrapping, and unwrapping for the TFHE-KMS.
//
// Key hierarchy:
//
//	Passphrase → Argon2id → Master Key (256-bit)
//	Master Key → HKDF-SHA256 → CEK (per purpose)
//	CEK → HPKE wrap → Member-specific wrapped key
package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// Argon2id parameters per architecture spec.
	argon2Memory  = 256 * 1024 // 256 MiB
	argon2Time    = 4
	argon2Threads = 2
	argon2KeyLen  = 32 // 256-bit master key

	// Salt suffix appended to org_id for CEK derivation.
	cekSaltSuffix = "hanzo-kms-cek-v1"
)

// DeriveCEK derives a 256-bit Content Encryption Key from a passphrase and org salt
// using Argon2id. The result is deterministic for the same inputs.
func DeriveCEK(passphrase string, orgSalt []byte) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("crypto: passphrase is empty")
	}
	if len(orgSalt) == 0 {
		return nil, errors.New("crypto: org salt is empty")
	}

	// salt = orgSalt || "hanzo-kms-cek-v1"
	salt := append(append([]byte{}, orgSalt...), []byte(cekSaltSuffix)...)

	key := argon2.IDKey(
		[]byte(passphrase),
		salt,
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)
	return key, nil
}

// DeriveSubkey derives a purpose-specific subkey from a master key using HKDF-SHA256.
// The purpose string provides domain separation (e.g., "cek-aes256gcm", "wrapping-hpke").
func DeriveSubkey(masterKey []byte, purpose string) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("crypto: master key is empty")
	}
	if purpose == "" {
		return nil, errors.New("crypto: purpose is empty")
	}

	hkdfReader := hkdf.New(sha256.New, masterKey, nil, []byte(purpose))
	subkey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, subkey); err != nil {
		return nil, fmt.Errorf("crypto: hkdf: %w", err)
	}
	return subkey, nil
}
