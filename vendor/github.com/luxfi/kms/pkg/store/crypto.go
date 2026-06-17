package store

// AES-256-GCM Seal/Open helpers wrapping the generic SecretStore.
//
// This is the v1 envelope: master key (32 bytes, unsealed at boot) seals
// every Secret's DEK with AES-256-GCM. The DEK seals the plaintext.
//
// v2 (tracked upstream in luxfi/crypto/xwing): replace the master→DEK wrap
// with an ML-KEM-768 recipient-public-key encapsulation (`ModeStandard`
// "aead+mlkem"), so the master key is PQ-wrapped at rest. The struct field
// `WrappedDEK` is already shaped for that.
//
// Plaintext never leaves memory. The caller is responsible for zeroing
// the returned byte slice when done.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// envelopeVersion is the on-disk format version. Increment for breaking changes.
const envelopeVersion byte = 0x01

// ErrBadKey is returned when the master key is the wrong size.
var ErrBadKey = errors.New("crypto: master key must be 32 bytes")

// ErrBadEnvelope is returned when ciphertext layout is invalid.
var ErrBadEnvelope = errors.New("crypto: invalid envelope")

// Seal encrypts plaintext under a fresh per-secret DEK, then wraps the DEK
// under the master key. Returns a Secret ready to Put into the store.
//
// Envelope layout for Ciphertext:
//
//	version(1) || nonce(12) || ciphertext_with_tag(variable)
//	AAD = path + "/" + name + "/" + env
//
// WrappedDEK is AES-GCM(DEK, masterKey), same envelope shape, AAD=name.
func Seal(masterKey []byte, path, name, env string, plaintext []byte) (*Secret, error) {
	if len(masterKey) != 32 {
		return nil, ErrBadKey
	}

	// Fresh 256-bit DEK per secret.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("crypto: rand dek: %w", err)
	}

	// Seal plaintext under DEK with AAD binding path/name/env.
	aad := []byte(path + "/" + name + "/" + env)
	ct, err := aeadSeal(dek, aad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("crypto: seal plaintext: %w", err)
	}

	// Wrap DEK under master key, AAD binds the secret name (prevents swap).
	wrap, err := aeadSeal(masterKey, []byte(name), dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: wrap dek: %w", err)
	}

	// Zero the DEK.
	for i := range dek {
		dek[i] = 0
	}

	now := time.Now().UTC()
	return &Secret{
		Name:       name,
		Path:       path,
		Env:        env,
		Ciphertext: ct,
		WrappedDEK: wrap,
		Scheme:     ModeStandard,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

// Open inverts Seal. Returns plaintext on success.
// The caller must zero the returned slice after use.
func Open(masterKey []byte, secret *Secret) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, ErrBadKey
	}
	if secret == nil {
		return nil, ErrBadEnvelope
	}

	dek, err := aeadOpen(masterKey, []byte(secret.Name), secret.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap dek: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	aad := []byte(secret.Path + "/" + secret.Name + "/" + secret.Env)
	pt, err := aeadOpen(dek, aad, secret.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: open plaintext: %w", err)
	}
	return pt, nil
}

// aeadSeal produces: version(1) || nonce(12) || ct||tag
func aeadSeal(key, aad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 0, 1+len(nonce)+len(ct))
	out = append(out, envelopeVersion)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// aeadOpen parses the envelope and returns plaintext.
func aeadOpen(key, aad, envelope []byte) ([]byte, error) {
	if len(envelope) < 1+12+16 {
		return nil, ErrBadEnvelope
	}
	if envelope[0] != envelopeVersion {
		return nil, fmt.Errorf("crypto: unsupported envelope version 0x%02x", envelope[0])
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	nonce := envelope[1 : 1+ns]
	ct := envelope[1+ns:]
	return gcm.Open(nil, nonce, ct, aad)
}
