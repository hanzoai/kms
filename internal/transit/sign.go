package transit

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// SignRequest is the input for transit sign.
type SignRequest struct {
	Input string `json:"input"` // base64-encoded message
}

// SignResponse is the output of transit sign.
type SignResponse struct {
	Signature string `json:"signature"` // base64-encoded Ed25519 signature
	KeyVersion int   `json:"key_version"`
}

// VerifyRequest is the input for transit verify.
type VerifyRequest struct {
	Input     string `json:"input"`     // base64-encoded message
	Signature string `json:"signature"` // base64-encoded signature
}

// VerifyResponse is the output of transit verify.
type VerifyResponse struct {
	Valid bool `json:"valid"`
}

// Sign signs a message with the latest version of the named Ed25519 key.
func (e *Engine) Sign(name string, req SignRequest) (*SignResponse, error) {
	rec, ring, err := e.GetKeyRing(name)
	if err != nil {
		return nil, err
	}
	if rec.KeyType != KeyTypeEd25519 {
		return nil, fmt.Errorf("transit: key %q is %s, not ed25519", name, rec.KeyType)
	}

	msg, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		return nil, fmt.Errorf("transit: decode input: %w", err)
	}

	seed := ring[rec.LatestVersion]
	privKey := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(privKey, msg)

	return &SignResponse{
		Signature:  base64.StdEncoding.EncodeToString(sig),
		KeyVersion: rec.LatestVersion,
	}, nil
}

// Verify checks a signature against the Ed25519 key.
// It tries the latest version first, then falls back to all versions.
func (e *Engine) Verify(name string, req VerifyRequest) (*VerifyResponse, error) {
	rec, ring, err := e.GetKeyRing(name)
	if err != nil {
		return nil, err
	}
	if rec.KeyType != KeyTypeEd25519 {
		return nil, fmt.Errorf("transit: key %q is %s, not ed25519", name, rec.KeyType)
	}

	msg, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		return nil, fmt.Errorf("transit: decode input: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return nil, fmt.Errorf("transit: decode signature: %w", err)
	}

	// Try all key versions (latest first for fast path).
	for v := rec.LatestVersion; v >= 1; v-- {
		seed, ok := ring[v]
		if !ok {
			continue
		}
		privKey := ed25519.NewKeyFromSeed(seed)
		pubKey := privKey.Public().(ed25519.PublicKey)
		if ed25519.Verify(pubKey, msg, sig) {
			return &VerifyResponse{Valid: true}, nil
		}
	}

	return &VerifyResponse{Valid: false}, nil
}
