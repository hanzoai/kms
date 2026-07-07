package kms

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/luxfi/kms/pkg/store"
)

// TestRequireEncryptionKeyAtBoot (HIGH-2) proves the fail-closed boot guard:
// prod/HA refuses to boot without a 32-byte at-rest key (which would otherwise
// write a plaintext KEYREGISTRY + plaintext secrets to the RETAIN volume);
// dev/test single-node may run keyless.
func TestRequireEncryptionKeyAtBoot(t *testing.T) {
	good := bytes.Repeat([]byte{1}, 32)
	short := bytes.Repeat([]byte{1}, 16)

	cases := []struct {
		name    string
		env     string
		role    replicaRole
		ha      string
		key     []byte
		wantErr bool
	}{
		{"prod + no key -> fatal", "prod", rolePrimary, "", nil, true},
		{"prod + short key -> fatal", "prod", rolePrimary, "", short, true},
		{"prod + 32B key -> ok", "prod", rolePrimary, "", good, false},
		{"main + no key -> fatal", "main", rolePrimary, "", nil, true},
		{"dev + no key -> ok (keyless dev)", "dev", rolePrimary, "", nil, false},
		{"test + no key -> ok", "test", rolePrimary, "", nil, false},
		{"empty env + no key -> ok", "", rolePrimary, "", nil, false},
		{"dev + HA + no key -> fatal (HA forces key)", "dev", rolePrimary, "true", nil, true},
		{"dev + follower + no key -> ok", "dev", roleFollower, "", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("KMS_HA", c.ha)
			err := requireEncryptionKeyAtBoot(c.env, c.role, c.key)
			if (err != nil) != c.wantErr {
				t.Fatalf("requireEncryptionKeyAtBoot(%q, %v, ha=%q, keylen=%d) err=%v, wantErr=%v",
					c.env, c.role, c.ha, len(c.key), err, c.wantErr)
			}
		})
	}
}

// TestSealValueRoundTrip (HIGH-2) proves the app-side Seal envelope is wired:
// with a key the stored record is real ciphertext (not the plaintext value),
// round-trips through the store, and a WRONG key fails closed. Without a key
// it falls back to raw (dev), and openValue reads both shapes.
func TestSealValueRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	wrong := bytes.Repeat([]byte{8}, 32)
	const plaintext = "super-secret-value"

	db := openTestDB(t, filepath.Join(t.TempDir(), "db"))
	s := store.NewSecretStore(db)

	t.Run("sealed: ciphertext is not the plaintext, round-trips", func(t *testing.T) {
		sec, err := sealValue(key, "/orgs/hanzo", "API_KEY", "prod", plaintext)
		if err != nil {
			t.Fatalf("sealValue: %v", err)
		}
		if len(sec.WrappedDEK) == 0 {
			t.Fatal("sealed secret must have a WrappedDEK (envelope not applied)")
		}
		if bytes.Contains(sec.Ciphertext, []byte(plaintext)) {
			t.Fatal("stored Ciphertext contains the plaintext value — the Seal envelope is NOT protecting at-rest")
		}
		if err := s.Put(sec); err != nil {
			t.Fatalf("put: %v", err)
		}
		got, err := s.Get("/orgs/hanzo", "API_KEY", "prod")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		val, err := openValue(key, got)
		if err != nil || val != plaintext {
			t.Fatalf("openValue = (%q, %v), want (%q, nil)", val, err, plaintext)
		}
	})

	t.Run("wrong key fails closed (no plaintext leak)", func(t *testing.T) {
		sec, _ := sealValue(key, "/orgs/hanzo", "WRONGKEY", "prod", plaintext)
		if _, err := openValue(wrong, sec); err == nil {
			t.Fatal("openValue with the WRONG master key must fail, not return garbage/plaintext")
		}
	})

	t.Run("keyless dev fallback is raw + readable", func(t *testing.T) {
		sec, err := sealValue(nil, "/orgs/hanzo", "DEV", "dev", plaintext)
		if err != nil {
			t.Fatalf("sealValue(nil): %v", err)
		}
		if len(sec.WrappedDEK) != 0 {
			t.Fatal("keyless fallback must not set WrappedDEK")
		}
		val, err := openValue(nil, sec)
		if err != nil || val != plaintext {
			t.Fatalf("openValue(nil raw) = (%q, %v), want (%q, nil)", val, err, plaintext)
		}
	})
}

// TestZAPServerGatedOnFollower (MEDIUM-1) proves the ZAP write listener never
// starts on a follower — the role check fires BEFORE the master-key path, so
// even a fully-configured master key cannot bring up a ZAP write path on a
// standby.
func TestZAPServerGatedOnFollower(t *testing.T) {
	t.Setenv("KMS_MASTER_KEY_B64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	db := openTestDB(t, filepath.Join(t.TempDir(), "db"))
	s := store.NewSecretStore(db)
	cfg := EmbedConfig{ZAPPort: 9999, NodeID: "kms-luxfi-1"}

	if node := startZAPSecretServer(s, cfg, roleFollower); node != nil {
		node.Stop()
		t.Fatal("follower must NOT start a ZAP secrets server (write-path bypass of followerReadOnly)")
	}
}
