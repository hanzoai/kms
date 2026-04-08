package transit

import (
	"encoding/base64"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	e, cleanup := newTestEngine(t)
	defer cleanup()

	err := e.CreateKey(CreateKeyRequest{Name: "test-ed", Type: KeyTypeEd25519})
	if err != nil {
		t.Fatal(err)
	}

	msg := base64.StdEncoding.EncodeToString([]byte("sign this"))

	sig, err := e.Sign("test-ed", SignRequest{Input: msg})
	if err != nil {
		t.Fatal(err)
	}
	if sig.Signature == "" {
		t.Fatal("empty signature")
	}
	if sig.KeyVersion != 1 {
		t.Errorf("key_version: got %d, want 1", sig.KeyVersion)
	}

	// Verify.
	ver, err := e.Verify("test-ed", VerifyRequest{Input: msg, Signature: sig.Signature})
	if err != nil {
		t.Fatal(err)
	}
	if !ver.Valid {
		t.Error("expected valid signature")
	}

	// Verify with wrong message.
	wrong := base64.StdEncoding.EncodeToString([]byte("wrong message"))
	ver2, err := e.Verify("test-ed", VerifyRequest{Input: wrong, Signature: sig.Signature})
	if err != nil {
		t.Fatal(err)
	}
	if ver2.Valid {
		t.Error("expected invalid signature for wrong message")
	}
}

func TestSignVerifyAfterRotation(t *testing.T) {
	e, cleanup := newTestEngine(t)
	defer cleanup()

	err := e.CreateKey(CreateKeyRequest{Name: "rot-ed", Type: KeyTypeEd25519})
	if err != nil {
		t.Fatal(err)
	}

	msg := base64.StdEncoding.EncodeToString([]byte("data"))

	// Sign with v1.
	sig1, err := e.Sign("rot-ed", SignRequest{Input: msg})
	if err != nil {
		t.Fatal(err)
	}

	// Rotate.
	if err := e.RotateKey("rot-ed"); err != nil {
		t.Fatal(err)
	}

	// v1 signature still verifies (fallback to old versions).
	ver1, err := e.Verify("rot-ed", VerifyRequest{Input: msg, Signature: sig1.Signature})
	if err != nil {
		t.Fatal(err)
	}
	if !ver1.Valid {
		t.Error("expected v1 signature to still verify after rotation")
	}

	// Sign with v2.
	sig2, err := e.Sign("rot-ed", SignRequest{Input: msg})
	if err != nil {
		t.Fatal(err)
	}
	if sig2.KeyVersion != 2 {
		t.Errorf("key_version: got %d, want 2", sig2.KeyVersion)
	}

	ver2, err := e.Verify("rot-ed", VerifyRequest{Input: msg, Signature: sig2.Signature})
	if err != nil {
		t.Fatal(err)
	}
	if !ver2.Valid {
		t.Error("expected v2 signature to verify")
	}
}

func TestSignWrongKeyType(t *testing.T) {
	e, cleanup := newTestEngine(t)
	defer cleanup()

	err := e.CreateKey(CreateKeyRequest{Name: "aes-key", Type: KeyTypeAES256GCM})
	if err != nil {
		t.Fatal(err)
	}

	msg := base64.StdEncoding.EncodeToString([]byte("test"))
	_, err = e.Sign("aes-key", SignRequest{Input: msg})
	if err == nil {
		t.Fatal("expected error when signing with AES key")
	}
}
