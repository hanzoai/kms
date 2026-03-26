// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package store

import (
	"crypto/rand"
	"testing"
)

func testEncryptionKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func TestNewStore(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		keyLen  int
		wantErr bool
	}{
		{"valid 32-byte key", t.TempDir(), 32, false},
		{"valid 16-byte key", t.TempDir(), 16, false},
		{"valid 24-byte key", t.TempDir(), 24, false},
		{"invalid 15-byte key", t.TempDir(), 15, true},
		{"empty path", "", 32, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			s, err := NewStore(tt.path, key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewStore() error = %v, wantErr %v", err, tt.wantErr)
			}
			if s != nil {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPutGetSecret(t *testing.T) {
	s, err := NewStore(t.TempDir(), testEncryptionKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	tests := []struct {
		name    string
		org     string
		key     string
		value   []byte
		wantErr bool
	}{
		{"basic", "acme", "db-password", []byte("encrypted-blob-1"), false},
		{"another org", "globex", "api-key", []byte("encrypted-blob-2"), false},
		{"empty value", "acme", "empty", []byte{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.PutSecret(tt.org, tt.key, tt.value); err != nil {
				t.Fatalf("PutSecret() error = %v", err)
			}
			got, err := s.GetSecret(tt.org, tt.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetSecret() error = %v", err)
			}
			if string(got) != string(tt.value) {
				t.Fatalf("GetSecret() = %q, want %q", got, tt.value)
			}
		})
	}
}

func TestGetSecretNotFound(t *testing.T) {
	s, err := NewStore(t.TempDir(), testEncryptionKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.GetSecret("acme", "nonexistent")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestListSecrets(t *testing.T) {
	s, err := NewStore(t.TempDir(), testEncryptionKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Insert secrets for two orgs.
	secrets := map[string][]string{
		"acme":   {"db-pass", "api-key", "tls-cert"},
		"globex": {"token"},
	}
	for org, keys := range secrets {
		for _, k := range keys {
			if err := s.PutSecret(org, k, []byte("data")); err != nil {
				t.Fatal(err)
			}
		}
	}

	// List for acme.
	got, err := s.ListSecrets("acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("ListSecrets(acme) returned %d keys, want 3", len(got))
	}

	// List for globex.
	got, err = s.ListSecrets("globex")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("ListSecrets(globex) returned %d keys, want 1", len(got))
	}

	// List for nonexistent org.
	got, err = s.ListSecrets("empty-org")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("ListSecrets(empty-org) returned %d keys, want 0", len(got))
	}
}

func TestPutGetShard(t *testing.T) {
	s, err := NewStore(t.TempDir(), testEncryptionKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	shard := []byte("shamir-shard-data-for-node-1")
	if err := s.PutShard("acme", shard); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetShard("acme")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(shard) {
		t.Fatalf("GetShard() = %q, want %q", got, shard)
	}
}

func TestCRDTOps(t *testing.T) {
	s, err := NewStore(t.TempDir(), testEncryptionKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Write 5 CRDT ops.
	for i := 0; i < 5; i++ {
		op := []byte{byte(i), byte(i + 10)}
		if err := s.PutCRDTOp("acme", op); err != nil {
			t.Fatalf("PutCRDTOp(%d) error = %v", i, err)
		}
	}

	// Read all ops (since 0).
	ops, err := s.GetCRDTOps("acme", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 5 {
		t.Fatalf("GetCRDTOps(since=0) returned %d ops, want 5", len(ops))
	}

	// Read ops since seq 3.
	ops, err = s.GetCRDTOps("acme", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 {
		t.Fatalf("GetCRDTOps(since=3) returned %d ops, want 2", len(ops))
	}
}

func TestStoreCloseErrors(t *testing.T) {
	s, err := NewStore(t.TempDir(), testEncryptionKey())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if err := s.PutSecret("acme", "key", []byte("data")); err != ErrClosed {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
	if _, err := s.GetSecret("acme", "key"); err != ErrClosed {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
	if _, err := s.ListSecrets("acme"); err != ErrClosed {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}
