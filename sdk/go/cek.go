// Copyright (C) 2020-2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/encryption"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// cekSaltSuffix is appended to org_id to create the Argon2id salt.
	cekSaltSuffix = "hanzo-kms-cek-v1"

	// cekHKDFInfo is the HKDF info parameter for CEK derivation.
	cekHKDFInfo = "cek-aes256gcm"

	// hpkeWrappingInfo is the HPKE info parameter for CEK wrapping.
	hpkeWrappingInfo = "hanzo-kms-cek"

	// cekSize is the CEK size in bytes (256-bit AES key).
	cekSize = 32

	// Argon2id parameters per architecture spec: m=256MiB, t=4, p=2.
	argon2Memory  = 256 * 1024 // 256 MiB in KiB
	argon2Time    = 4
	argon2Threads = 2

	// gcmNonceSize is the standard GCM nonce size.
	gcmNonceSize = 12
)

// deriveSalt produces the Argon2id salt from the org slug.
// salt = SHA-256(orgSlug || cekSaltSuffix)
func deriveSalt(orgSlug string) []byte {
	h := sha256.Sum256([]byte(orgSlug + cekSaltSuffix))
	return h[:]
}

// DeriveMasterKey derives the 256-bit master key from a passphrase using Argon2id.
// This is the first step in the key hierarchy; the CEK is then derived from
// the master key via HKDF.
func DeriveMasterKey(passphrase string, orgSlug string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("kms: passphrase must not be empty")
	}
	if orgSlug == "" {
		return nil, errors.New("kms: org slug must not be empty")
	}

	salt := deriveSalt(orgSlug)
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, cekSize)
	return key, nil
}

// DeriveCEK derives the Customer Encryption Key from the master key using HKDF-SHA256.
// The CEK is used for AES-256-GCM encryption of secret payloads.
// It never leaves the client.
func DeriveCEK(masterKey []byte, orgSlug string) ([]byte, error) {
	if len(masterKey) != cekSize {
		return nil, fmt.Errorf("kms: master key must be %d bytes, got %d", cekSize, len(masterKey))
	}

	hkdfReader := hkdf.New(sha256.New, masterKey, []byte(orgSlug), []byte(cekHKDFInfo))
	cek := make([]byte, cekSize)
	if _, err := hkdfReader.Read(cek); err != nil {
		return nil, fmt.Errorf("kms: hkdf derive cek: %w", err)
	}
	return cek, nil
}

// WrapCEKForMember wraps the CEK with a member's HPKE public key using
// ML-KEM-768+X25519 hybrid HPKE (post-quantum).
func WrapCEKForMember(cek []byte, memberPubKey []byte) ([]byte, error) {
	if len(cek) != cekSize {
		return nil, fmt.Errorf("kms: cek must be %d bytes, got %d", cekSize, len(cek))
	}
	if len(memberPubKey) == 0 {
		return nil, errors.New("kms: member public key must not be empty")
	}

	wrapped, err := encryption.HybridHPKESeal(memberPubKey, []byte(hpkeWrappingInfo), cek)
	if err != nil {
		return nil, fmt.Errorf("kms: wrap cek: %w", err)
	}
	return wrapped, nil
}

// UnwrapCEK unwraps a CEK using the member's HPKE private key.
func UnwrapCEK(wrappedCEK []byte, memberPrivKey []byte) ([]byte, error) {
	if len(wrappedCEK) == 0 {
		return nil, errors.New("kms: wrapped cek must not be empty")
	}
	if len(memberPrivKey) == 0 {
		return nil, errors.New("kms: member private key must not be empty")
	}

	kp, err := encryption.HybridHPKEKeyPairFromBytes(memberPrivKey)
	if err != nil {
		return nil, fmt.Errorf("kms: parse member private key: %w", err)
	}

	cek, err := encryption.HybridHPKEOpen(kp, []byte(hpkeWrappingInfo), wrappedCEK)
	if err != nil {
		return nil, fmt.Errorf("kms: unwrap cek: %w", err)
	}
	return cek, nil
}

// sealAESGCM encrypts plaintext with AES-256-GCM using a random nonce.
// Returns nonce || ciphertext || tag.
func sealAESGCM(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("kms: generate nonce: %w", err)
	}

	// Seal appends ciphertext+tag after nonce.
	out := gcm.Seal(nonce, nonce, plaintext, aad)
	return out, nil
}

// openAESGCM decrypts an AES-256-GCM ciphertext.
// Expects nonce || ciphertext || tag as input.
func openAESGCM(key, data, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	if len(data) < gcmNonceSize {
		return nil, errors.New("kms: ciphertext too short")
	}

	nonce := data[:gcmNonceSize]
	ct := data[gcmNonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("kms: decrypt: %w", err)
	}
	return plaintext, nil
}

// newGCM creates an AES-256-GCM cipher.AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != cekSize {
		return nil, fmt.Errorf("kms: aes-256-gcm requires %d-byte key, got %d", cekSize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kms: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kms: gcm: %w", err)
	}
	return gcm, nil
}
