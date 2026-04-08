package transit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// EncryptRequest is the input for transit encrypt.
type EncryptRequest struct {
	Plaintext string `json:"plaintext"` // base64-encoded
}

// EncryptResponse is the output of transit encrypt.
type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"` // format: kms:v{N}:{base64}
}

// DecryptRequest is the input for transit decrypt.
type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"` // format: kms:v{N}:{base64}
}

// DecryptResponse is the output of transit decrypt.
type DecryptResponse struct {
	Plaintext string `json:"plaintext"` // base64-encoded
}

// Encrypt encrypts plaintext using the latest version of the named AES-256-GCM key.
func (e *Engine) Encrypt(name string, req EncryptRequest) (*EncryptResponse, error) {
	rec, ring, err := e.GetKeyRing(name)
	if err != nil {
		return nil, err
	}
	if rec.KeyType != KeyTypeAES256GCM {
		return nil, fmt.Errorf("transit: key %q is %s, not aes-256-gcm", name, rec.KeyType)
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("transit: decode plaintext: %w", err)
	}

	key := ring[rec.LatestVersion]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("transit: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("transit: gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("transit: nonce: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	encoded := base64.StdEncoding.EncodeToString(sealed)

	return &EncryptResponse{
		Ciphertext: fmt.Sprintf("kms:v%d:%s", rec.LatestVersion, encoded),
	}, nil
}

// Decrypt decrypts ciphertext using the versioned AES-256-GCM key.
func (e *Engine) Decrypt(name string, req DecryptRequest) (*DecryptResponse, error) {
	rec, ring, err := e.GetKeyRing(name)
	if err != nil {
		return nil, err
	}
	if rec.KeyType != KeyTypeAES256GCM {
		return nil, fmt.Errorf("transit: key %q is %s, not aes-256-gcm", name, rec.KeyType)
	}

	version, b64, err := parseCiphertext(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	key, ok := ring[version]
	if !ok {
		return nil, fmt.Errorf("transit: key version %d not found", version)
	}

	sealed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("transit: decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("transit: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("transit: gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize {
		return nil, fmt.Errorf("transit: ciphertext too short")
	}

	plaintext, err := gcm.Open(nil, sealed[:nonceSize], sealed[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("transit: decrypt: %w", err)
	}

	return &DecryptResponse{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}, nil
}

func parseCiphertext(s string) (int, string, error) {
	var version int
	var b64 string
	n, err := fmt.Sscanf(s, "kms:v%d:%s", &version, &b64)
	if err != nil || n != 2 {
		return 0, "", fmt.Errorf("transit: invalid ciphertext format (expected kms:v{N}:{base64})")
	}
	return version, b64, nil
}
