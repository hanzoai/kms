// Copyright (C) 2020-2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kms

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient_ValidConfig(t *testing.T) {
	c, err := NewClient(Config{
		Nodes:     []string{"https://node1:9999"},
		OrgSlug:   "test-org",
		Threshold: 1,
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if c.orgSlug != "test-org" {
		t.Errorf("expected orgSlug 'test-org', got %q", c.orgSlug)
	}
	if c.threshold != 1 {
		t.Errorf("expected threshold 1, got %d", c.threshold)
	}
	if c.IsUnlocked() {
		t.Error("expected client to start locked")
	}
}

func TestNewClient_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "no nodes",
			cfg:  Config{OrgSlug: "test", Threshold: 1},
		},
		{
			name: "no org slug",
			cfg:  Config{Nodes: []string{"n1"}, Threshold: 1},
		},
		{
			name: "zero threshold",
			cfg:  Config{Nodes: []string{"n1"}, OrgSlug: "test", Threshold: 0},
		},
		{
			name: "threshold exceeds nodes",
			cfg:  Config{Nodes: []string{"n1"}, OrgSlug: "test", Threshold: 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestDeriveMasterKey_Deterministic(t *testing.T) {
	k1, err := DeriveMasterKey("test-passphrase", "test-org")
	if err != nil {
		t.Fatalf("derive 1: %v", err)
	}
	k2, err := DeriveMasterKey("test-passphrase", "test-org")
	if err != nil {
		t.Fatalf("derive 2: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("same passphrase + org should produce same master key")
	}
}

func TestDeriveMasterKey_DifferentOrgs(t *testing.T) {
	k1, err := DeriveMasterKey("same-pass", "org-a")
	if err != nil {
		t.Fatalf("derive org-a: %v", err)
	}
	k2, err := DeriveMasterKey("same-pass", "org-b")
	if err != nil {
		t.Fatalf("derive org-b: %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Error("different orgs should produce different master keys")
	}
}

func TestDeriveMasterKey_DifferentPassphrases(t *testing.T) {
	k1, err := DeriveMasterKey("pass-a", "same-org")
	if err != nil {
		t.Fatalf("derive pass-a: %v", err)
	}
	k2, err := DeriveMasterKey("pass-b", "same-org")
	if err != nil {
		t.Fatalf("derive pass-b: %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Error("different passphrases should produce different master keys")
	}
}

func TestDeriveMasterKey_Validation(t *testing.T) {
	if _, err := DeriveMasterKey("", "org"); err == nil {
		t.Error("expected error for empty passphrase")
	}
	if _, err := DeriveMasterKey("pass", ""); err == nil {
		t.Error("expected error for empty org")
	}
}

func TestDeriveCEK_FromMasterKey(t *testing.T) {
	mk, err := DeriveMasterKey("passphrase", "org")
	if err != nil {
		t.Fatal(err)
	}

	cek, err := DeriveCEK(mk, "org")
	if err != nil {
		t.Fatal(err)
	}

	if len(cek) != cekSize {
		t.Errorf("expected CEK size %d, got %d", cekSize, len(cek))
	}

	// CEK should be different from master key.
	if bytes.Equal(cek, mk) {
		t.Error("CEK should differ from master key")
	}

	// CEK derivation should be deterministic.
	cek2, err := DeriveCEK(mk, "org")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cek, cek2) {
		t.Error("CEK derivation should be deterministic")
	}
}

func TestDeriveCEK_WrongKeySize(t *testing.T) {
	_, err := DeriveCEK([]byte("short"), "org")
	if err == nil {
		t.Error("expected error for wrong key size")
	}
}

func TestAESGCM_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("hello, zero-knowledge world")
	aad := []byte("test-org")

	ct, err := sealAESGCM(key, plaintext, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Ciphertext should be longer than plaintext (nonce + tag).
	if len(ct) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext")
	}

	// Ciphertext should not contain plaintext.
	if bytes.Contains(ct, plaintext) {
		t.Error("ciphertext should not contain plaintext")
	}

	pt, err := openAESGCM(key, ct, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", pt, plaintext)
	}
}

func TestAESGCM_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("secret data")
	aad := []byte("org")

	ct, err := sealAESGCM(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF

	_, err = openAESGCM(wrongKey, ct, aad)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestAESGCM_WrongAAD(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("secret data")

	ct, err := sealAESGCM(key, plaintext, []byte("org-a"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = openAESGCM(key, ct, []byte("org-b"))
	if err == nil {
		t.Error("expected error when decrypting with wrong AAD")
	}
}

func TestAESGCM_TruncatedCiphertext(t *testing.T) {
	key := make([]byte, 32)

	_, err := openAESGCM(key, []byte("short"), []byte("org"))
	if err == nil {
		t.Error("expected error for truncated ciphertext")
	}
}

func TestAESGCM_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	ct, err := sealAESGCM(key, []byte{}, []byte("org"))
	if err != nil {
		t.Fatal(err)
	}

	pt, err := openAESGCM(key, ct, []byte("org"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(pt))
	}
}

func TestUnlockLock(t *testing.T) {
	c, err := NewClient(Config{
		Nodes:     []string{"https://node1:9999"},
		OrgSlug:   "test-org",
		Threshold: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	if c.IsUnlocked() {
		t.Error("should start locked")
	}

	if err := c.Unlock("my-passphrase"); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if !c.IsUnlocked() {
		t.Error("should be unlocked after Unlock")
	}

	// getCEK should work when unlocked.
	cek, err := c.getCEK()
	if err != nil {
		t.Fatalf("getCEK: %v", err)
	}
	if len(cek) != cekSize {
		t.Errorf("expected CEK size %d, got %d", cekSize, len(cek))
	}

	c.Lock()

	if c.IsUnlocked() {
		t.Error("should be locked after Lock")
	}

	// getCEK should fail when locked.
	_, err = c.getCEK()
	if err == nil {
		t.Error("expected error from getCEK when locked")
	}
}

func TestUnlock_Deterministic(t *testing.T) {
	cfg := Config{
		Nodes:     []string{"https://node1:9999"},
		OrgSlug:   "deterministic-org",
		Threshold: 1,
	}

	c1, _ := NewClient(cfg)
	c1.Unlock("passphrase-x")
	cek1, _ := c1.getCEK()

	c2, _ := NewClient(cfg)
	c2.Unlock("passphrase-x")
	cek2, _ := c2.getCEK()

	if !bytes.Equal(cek1, cek2) {
		t.Error("same passphrase + org should produce same CEK across clients")
	}

	c1.Lock()
	c2.Lock()
}

func TestBase64_RoundTrip(t *testing.T) {
	original := []byte{0, 1, 2, 255, 254, 253}
	encoded := base64URLEncode(original)
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, decoded) {
		t.Error("base64 round-trip failed")
	}
}

func TestEndToEnd_EncryptDecrypt(t *testing.T) {
	// This tests the full client-side crypto path without MPC nodes:
	// derive CEK -> encrypt secret -> decrypt secret.

	cfg := Config{
		Nodes:     []string{"https://node1:9999"},
		OrgSlug:   "e2e-org",
		Threshold: 1,
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Unlock("e2e-passphrase"); err != nil {
		t.Fatal(err)
	}
	defer c.Lock()

	cek, err := c.getCEK()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(cek)

	aad := []byte(c.orgSlug)

	// Encrypt a secret name and value.
	secretName := "DATABASE_URL"
	secretValue := []byte("postgresql://user:pass@host:5432/db")

	encName, err := sealAESGCM(cek, []byte(secretName), aad)
	if err != nil {
		t.Fatal(err)
	}
	encValue, err := sealAESGCM(cek, secretValue, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt them back.
	decName, err := openAESGCM(cek, encName, aad)
	if err != nil {
		t.Fatal(err)
	}
	decValue, err := openAESGCM(cek, encValue, aad)
	if err != nil {
		t.Fatal(err)
	}

	if string(decName) != secretName {
		t.Errorf("name: got %q, want %q", decName, secretName)
	}
	if !bytes.Equal(decValue, secretValue) {
		t.Errorf("value: got %q, want %q", decValue, secretValue)
	}
}

func TestClient_SetGet_WithMockServer(t *testing.T) {
	// Mock MPC node that stores encrypted blobs in memory.
	store := make(map[string][]byte)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var es encryptedSecret
			if err := json.NewDecoder(r.Body).Decode(&es); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			key := base64URLEncode(es.Key)
			store[key] = es.Value
			w.WriteHeader(http.StatusOK)

		case http.MethodGet:
			// For GET, return the first stored secret.
			for _, v := range store {
				resp := encryptedSecret{Value: v}
				json.NewEncoder(w).Encode(resp)
				return
			}
			http.Error(w, "not found", http.StatusNotFound)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	c, err := NewClient(Config{
		Nodes:     []string{srv.URL},
		OrgSlug:   "mock-org",
		Threshold: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Unlock("mock-passphrase"); err != nil {
		t.Fatal(err)
	}
	defer c.Lock()

	// Set a secret.
	secretValue := []byte("s3cr3t-value-42")
	if err := c.Set("MY_SECRET", secretValue); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Verify a blob was stored.
	if len(store) == 0 {
		t.Fatal("expected at least one entry in mock store")
	}

	// Verify stored blob is encrypted (not plaintext).
	for _, v := range store {
		if bytes.Contains(v, secretValue) {
			t.Error("stored blob should be encrypted, not plaintext")
		}
	}
}

func TestClient_Status_WithMockServer(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthy.Close()

	c, err := NewClient(Config{
		Nodes:     []string{healthy.URL, unhealthy.URL},
		OrgSlug:   "status-org",
		Threshold: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	statuses, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}

	if len(statuses) != 2 {
		t.Fatalf("expected 2 statuses, got %d", len(statuses))
	}

	// First node should be healthy.
	if !statuses[0].Healthy {
		t.Error("expected first node to be healthy")
	}

	// Second node should be unhealthy.
	if statuses[1].Healthy {
		t.Error("expected second node to be unhealthy")
	}
}

func TestClient_Bootstrap_WithMockServer(t *testing.T) {
	var receivedBodies []bootstrapRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req bootstrapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		receivedBodies = append(receivedBodies, req)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewClient(Config{
		Nodes:     []string{srv.URL},
		OrgSlug:   "bootstrap-org",
		Threshold: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Bootstrap("bootstrap-pass"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if !c.IsUnlocked() {
		t.Error("expected client to be unlocked after bootstrap")
	}

	if len(receivedBodies) != 1 {
		t.Fatalf("expected 1 bootstrap request, got %d", len(receivedBodies))
	}

	req := receivedBodies[0]
	if req.OrgSlug != "bootstrap-org" {
		t.Errorf("expected org slug 'bootstrap-org', got %q", req.OrgSlug)
	}
	if req.Threshold != 1 {
		t.Errorf("expected threshold 1, got %d", req.Threshold)
	}
	if len(req.RecoveryVerificationHash) != 32 {
		t.Errorf("expected 32-byte verification hash, got %d bytes", len(req.RecoveryVerificationHash))
	}

	c.Lock()
}
