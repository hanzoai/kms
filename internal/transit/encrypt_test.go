package transit

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseCiphertext(t *testing.T) {
	version, b64, err := parseCiphertext("hanzo:v1:dGVzdA==")
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Errorf("version: got %d, want 1", version)
	}
	if b64 != "dGVzdA==" {
		t.Errorf("b64: got %q, want %q", b64, "dGVzdA==")
	}
}

func TestParseCiphertextInvalid(t *testing.T) {
	_, _, err := parseCiphertext("invalid")
	if err == nil {
		t.Fatal("expected error for invalid ciphertext format")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	e, cleanup := newTestEngine(t)
	defer cleanup()

	// Create a key.
	err := e.CreateKey(CreateKeyRequest{Name: "test-aes", Type: KeyTypeAES256GCM})
	if err != nil {
		t.Fatal(err)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("hello world"))

	// Encrypt.
	encResp, err := e.Encrypt("test-aes", EncryptRequest{Plaintext: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encResp.Ciphertext, "hanzo:v1:") {
		t.Errorf("ciphertext prefix: got %q", encResp.Ciphertext)
	}

	// Decrypt.
	decResp, err := e.Decrypt("test-aes", DecryptRequest{Ciphertext: encResp.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.StdEncoding.DecodeString(decResp.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "hello world" {
		t.Errorf("plaintext: got %q, want %q", string(decoded), "hello world")
	}
}

func TestEncryptDecryptAfterRotation(t *testing.T) {
	e, cleanup := newTestEngine(t)
	defer cleanup()

	err := e.CreateKey(CreateKeyRequest{Name: "rot-key", Type: KeyTypeAES256GCM})
	if err != nil {
		t.Fatal(err)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("secret data"))

	// Encrypt with v1.
	enc1, err := e.Encrypt("rot-key", EncryptRequest{Plaintext: plaintext})
	if err != nil {
		t.Fatal(err)
	}

	// Rotate key.
	if err := e.RotateKey("rot-key"); err != nil {
		t.Fatal(err)
	}

	// Encrypt with v2.
	enc2, err := e.Encrypt("rot-key", EncryptRequest{Plaintext: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc2.Ciphertext, "hanzo:v2:") {
		t.Errorf("expected v2 prefix, got %q", enc2.Ciphertext)
	}

	// Decrypt v1 ciphertext (old version still works).
	dec1, err := e.Decrypt("rot-key", DecryptRequest{Ciphertext: enc1.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	decoded1, _ := base64.StdEncoding.DecodeString(dec1.Plaintext)
	if string(decoded1) != "secret data" {
		t.Errorf("v1 decrypt: got %q", string(decoded1))
	}

	// Decrypt v2 ciphertext.
	dec2, err := e.Decrypt("rot-key", DecryptRequest{Ciphertext: enc2.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	decoded2, _ := base64.StdEncoding.DecodeString(dec2.Plaintext)
	if string(decoded2) != "secret data" {
		t.Errorf("v2 decrypt: got %q", string(decoded2))
	}
}
