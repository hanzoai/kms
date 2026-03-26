// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveCEK(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		orgSalt    []byte
		wantErr    bool
	}{
		{"valid", "my-secure-passphrase", []byte("org-uuid-1234"), false},
		{"empty passphrase", "", []byte("org-uuid"), true},
		{"empty salt", "pass", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeriveCEK(tt.passphrase, tt.orgSalt)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DeriveCEK() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(got) != 32 {
					t.Fatalf("DeriveCEK() returned %d bytes, want 32", len(got))
				}
			}
		})
	}
}

func TestDeriveCEKDeterministic(t *testing.T) {
	key1, err := DeriveCEK("password", []byte("org-1"))
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveCEK("password", []byte("org-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("DeriveCEK is not deterministic")
	}
}

func TestDeriveCEKDifferentInputs(t *testing.T) {
	key1, _ := DeriveCEK("password", []byte("org-1"))
	key2, _ := DeriveCEK("password", []byte("org-2"))
	key3, _ := DeriveCEK("different-password", []byte("org-1"))

	if bytes.Equal(key1, key2) {
		t.Fatal("different org salt produced same key")
	}
	if bytes.Equal(key1, key3) {
		t.Fatal("different passphrase produced same key")
	}
}

func TestDeriveSubkey(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	tests := []struct {
		name    string
		key     []byte
		purpose string
		wantErr bool
	}{
		{"cek", masterKey, "cek-aes256gcm", false},
		{"wrapping", masterKey, "wrapping-hpke", false},
		{"empty key", nil, "purpose", true},
		{"empty purpose", masterKey, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeriveSubkey(tt.key, tt.purpose)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DeriveSubkey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(got) != 32 {
				t.Fatalf("DeriveSubkey() returned %d bytes, want 32", len(got))
			}
		})
	}
}

func TestDeriveSubkeyDomainSeparation(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	k1, _ := DeriveSubkey(masterKey, "cek-aes256gcm")
	k2, _ := DeriveSubkey(masterKey, "wrapping-hpke")

	if bytes.Equal(k1, k2) {
		t.Fatal("different purposes produced same subkey")
	}
}

func TestWrapUnwrapCEK(t *testing.T) {
	pub, priv, err := GenerateHPKEKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	cek := make([]byte, 32)
	for i := range cek {
		cek[i] = byte(i + 100)
	}

	wrapped, err := WrapCEK(cek, pub)
	if err != nil {
		t.Fatalf("WrapCEK() error = %v", err)
	}

	unwrapped, err := UnwrapCEK(wrapped, priv)
	if err != nil {
		t.Fatalf("UnwrapCEK() error = %v", err)
	}

	if !bytes.Equal(cek, unwrapped) {
		t.Fatal("unwrapped CEK does not match original")
	}
}

func TestWrapCEKDifferentRecipients(t *testing.T) {
	pub1, _, err := GenerateHPKEKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, priv2, err := GenerateHPKEKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	cek := []byte("secret-cek-32-bytes-padded-here!")

	// Wrap to recipient 1.
	wrapped, err := WrapCEK(cek, pub1)
	if err != nil {
		t.Fatal(err)
	}

	// Try to unwrap with recipient 2's key — should fail.
	_, err = UnwrapCEK(wrapped, priv2)
	if err == nil {
		t.Fatal("UnwrapCEK with wrong key should fail")
	}
}

func TestWrapCEKEdgeCases(t *testing.T) {
	_, err := WrapCEK(nil, []byte("pub"))
	if err == nil {
		t.Fatal("WrapCEK(nil cek) should fail")
	}

	_, err = WrapCEK([]byte("cek"), nil)
	if err == nil {
		t.Fatal("WrapCEK(nil pub) should fail")
	}
}
