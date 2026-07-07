package kms

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	"github.com/luxfi/age"
)

// TestDeriveReplicationPassphrase (MEDIUM-4) proves the KDF is deterministic,
// key-dependent, and domain-separated from the raw master key.
func TestDeriveReplicationPassphrase(t *testing.T) {
	k1 := bytes.Repeat([]byte{1}, 32)
	k2 := bytes.Repeat([]byte{2}, 32)

	p1 := deriveReplicationPassphrase(k1)
	if p1 != deriveReplicationPassphrase(k1) {
		t.Fatal("passphrase derivation must be deterministic")
	}
	if p1 == deriveReplicationPassphrase(k2) {
		t.Fatal("different master keys must derive different passphrases")
	}
	if p1 == base64.RawStdEncoding.EncodeToString(k1) {
		t.Fatal("passphrase must be domain-separated from the raw master key")
	}
}

// TestAuthenticatedBackupUnforgeable (MEDIUM-4) is the core proof: a backup
// encrypted under the master-key-derived scrypt passphrase round-trips for a
// holder of the master key, but an attacker with S3 write access and NOT the
// master key can neither READ a legit backup nor FORGE a substitute our
// identity will load. This closes the age-X25519 forgery/substitution vector.
func TestAuthenticatedBackupUnforgeable(t *testing.T) {
	t.Setenv("KMS_REPLICATE_SCRYPT_LOGN", "10") // fast for tests
	master := bytes.Repeat([]byte{0x2a}, 32)
	attacker := bytes.Repeat([]byte{0x2b}, 32) // attacker's guess — NOT the master key

	rr, ri, err := deriveScryptBackupKeys(master)
	if err != nil {
		t.Fatalf("deriveScryptBackupKeys: %v", err)
	}

	// A legitimate backup encrypted to the master-derived recipient.
	var backup bytes.Buffer
	w, err := age.Encrypt(&backup, rr)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	const plaintext = "kms-backup-stream-bytes"
	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Master-key holder restores it.
	dec, err := age.Decrypt(bytes.NewReader(backup.Bytes()), ri)
	if err != nil {
		t.Fatalf("legit decrypt: %v", err)
	}
	got, _ := io.ReadAll(dec)
	if string(got) != plaintext {
		t.Fatalf("round-trip = %q, want %q", got, plaintext)
	}

	// Confidentiality: an attacker deriving from the WRONG key cannot read it.
	_, aiWrong, _ := deriveScryptBackupKeys(attacker)
	if _, err := age.Decrypt(bytes.NewReader(backup.Bytes()), aiWrong); err == nil {
		t.Fatal("attacker without the master key decrypted a backup (confidentiality broken)")
	}

	// Authenticity: an attacker FORGES a malicious backup with their own key;
	// our identity must REJECT it (they lack the master-derived passphrase).
	arWrong, _, _ := deriveScryptBackupKeys(attacker)
	var forged bytes.Buffer
	fw, _ := age.Encrypt(&forged, arWrong)
	_, _ = io.WriteString(fw, "MALICIOUS-INJECTED-SECRETS")
	_ = fw.Close()
	if _, err := age.Decrypt(bytes.NewReader(forged.Bytes()), ri); err == nil {
		t.Fatal("our identity accepted a FORGED backup (authenticity broken — substitution possible)")
	}
}

// TestBuildReplicatorConfigAuthenticatedByDefault (MEDIUM-4) proves kms-luxfi
// picks the authenticated (master-key scrypt) path by default — no explicit
// X25519 keypair needed — and that require-encryption with no key AND no
// recipient fails closed.
func TestBuildReplicatorConfigAuthenticatedByDefault(t *testing.T) {
	t.Setenv("KMS_REPLICATE_SCRYPT_LOGN", "10")
	t.Setenv("REPLICATE_S3_ENDPOINT", "http://s3.hanzo.svc:9000")
	t.Setenv("REPLICATE_REQUIRE_ENCRYPTION", "true")
	t.Setenv("REPLICATE_AGE_RECIPIENT", "") // no explicit keypair
	t.Setenv("REPLICATE_AGE_IDENTITY", "")

	t.Run("master key present -> authenticated scrypt", func(t *testing.T) {
		t.Setenv("KMS_ENCRYPTION_KEY_B64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
		cfg, enabled, err := buildReplicatorConfig("kms-luxfi-0")
		if err != nil || !enabled {
			t.Fatalf("buildReplicatorConfig: enabled=%v err=%v", enabled, err)
		}
		if cfg.AgeRecipient == nil || cfg.AgeIdentity == nil {
			t.Fatal("authenticated backup must set BOTH AgeRecipient and AgeIdentity (scrypt)")
		}
	})

	t.Run("no key + no recipient + require-encryption -> fatal", func(t *testing.T) {
		t.Setenv("KMS_ENCRYPTION_KEY_B64", "")
		if _, _, err := buildReplicatorConfig("kms-luxfi-0"); err == nil {
			t.Fatal("require-encryption with neither a key nor a recipient must refuse to boot")
		}
	})
}
