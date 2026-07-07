package kms

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/luxfi/age"
	"github.com/luxfi/kms/pkg/store"
	badger "github.com/luxfi/zapdb"
)

// testKey is a fixed 32-byte AES-256 key for the at-rest ZapDB encryption
// in these hermetic tests. Never a real key.
var testKey = bytes.Repeat([]byte{0x2a}, 32)

func openTestDB(t *testing.T, dir string) *badger.DB {
	t.Helper()
	opts := badger.DefaultOptions(dir).
		WithLogger(nil).
		WithEncryptionKey(testKey).
		WithIndexCacheSize(16 << 20)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("open zapdb at %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// putSecret mirrors embed.go's storage shape: the standalone kmsd stores
// the logical value in Secret.Ciphertext (protected by ZapDB block
// encryption at rest, NOT app-layer sealed).
func putSecret(t *testing.T, s *store.SecretStore, path, name, env, val string) {
	t.Helper()
	if err := s.Put(&store.Secret{Name: name, Path: path, Env: env, Ciphertext: []byte(val)}); err != nil {
		t.Fatalf("put %s/%s: %v", path, name, err)
	}
}

func getSecret(t *testing.T, s *store.SecretStore, path, name, env string) (string, bool) {
	t.Helper()
	sec, err := s.Get(path, name, env)
	if err != nil {
		return "", false
	}
	return string(sec.Ciphertext), true
}

// --- role derivation ---------------------------------------------------------

func TestPodOrdinal(t *testing.T) {
	cases := []struct {
		in     string
		want   int
		wantOk bool
	}{
		{"kms-luxfi-0", 0, true},
		{"kms-luxfi-1", 1, true},
		{"kms-luxfi-11", 11, true},
		{"kms", 0, false},
		{"kms-luxfi-", 0, false},
		{"kms-luxfi-x", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := podOrdinal(c.in)
		if ok != c.wantOk || (ok && got != c.want) {
			t.Errorf("podOrdinal(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.wantOk)
		}
	}
}

func TestResolveRole(t *testing.T) {
	// Clear anything the environment might carry in.
	for _, k := range []string{"KMS_REPLICA_ROLE", "KMS_HA", "KMS_PRIMARY_ORDINAL", "POD_NAME", "HOSTNAME"} {
		t.Setenv(k, "")
	}

	t.Run("default is primary (single node, pre-HA behaviour)", func(t *testing.T) {
		t.Setenv("KMS_HA", "")
		t.Setenv("KMS_REPLICA_ROLE", "")
		if got := resolveRole(); got != rolePrimary {
			t.Fatalf("default role = %v, want primary", got)
		}
	})

	t.Run("explicit override wins over ordinal", func(t *testing.T) {
		t.Setenv("KMS_HA", "true")
		t.Setenv("POD_NAME", "kms-luxfi-0") // ordinal would say primary
		t.Setenv("KMS_REPLICA_ROLE", "follower")
		if got := resolveRole(); got != roleFollower {
			t.Fatalf("override role = %v, want follower", got)
		}
	})

	t.Run("HA ordinal 0 is primary", func(t *testing.T) {
		t.Setenv("KMS_REPLICA_ROLE", "")
		t.Setenv("KMS_HA", "true")
		t.Setenv("KMS_PRIMARY_ORDINAL", "")
		t.Setenv("POD_NAME", "kms-luxfi-0")
		if got := resolveRole(); got != rolePrimary {
			t.Fatalf("ordinal-0 role = %v, want primary", got)
		}
	})

	t.Run("HA ordinal 1 is follower", func(t *testing.T) {
		t.Setenv("KMS_REPLICA_ROLE", "")
		t.Setenv("KMS_HA", "true")
		t.Setenv("KMS_PRIMARY_ORDINAL", "")
		t.Setenv("POD_NAME", "kms-luxfi-1")
		if got := resolveRole(); got != roleFollower {
			t.Fatalf("ordinal-1 role = %v, want follower", got)
		}
	})

	t.Run("KMS_PRIMARY_ORDINAL relocates the primary (promote)", func(t *testing.T) {
		t.Setenv("KMS_REPLICA_ROLE", "")
		t.Setenv("KMS_HA", "true")
		t.Setenv("KMS_PRIMARY_ORDINAL", "1")
		t.Setenv("POD_NAME", "kms-luxfi-1")
		if got := resolveRole(); got != rolePrimary {
			t.Fatalf("promoted ordinal-1 role = %v, want primary", got)
		}
		t.Setenv("POD_NAME", "kms-luxfi-0")
		if got := resolveRole(); got != roleFollower {
			t.Fatalf("demoted ordinal-0 role = %v, want follower", got)
		}
	})

	t.Run("HA without an ordinal falls back to primary (never dark)", func(t *testing.T) {
		t.Setenv("KMS_REPLICA_ROLE", "")
		t.Setenv("KMS_HA", "true")
		t.Setenv("POD_NAME", "")
		t.Setenv("HOSTNAME", "some-non-sts-host")
		if got := resolveRole(); got != rolePrimary {
			t.Fatalf("no-ordinal role = %v, want primary", got)
		}
	})
}

// --- replicator config + age wiring -----------------------------------------

func TestBuildReplicatorConfig(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	recipient := id.Recipient().String()
	identity := id.String()

	clearReplEnv := func(t *testing.T) {
		for _, k := range []string{
			"REPLICATE_S3_ENDPOINT", "REPLICATE_S3_BUCKET", "REPLICATE_S3_REGION",
			"REPLICATE_S3_ACCESS_KEY_ID", "REPLICATE_S3_SECRET_ACCESS_KEY",
			"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
			"REPLICATE_S3_PATH", "REPLICATE_PATH",
			"REPLICATE_AGE_RECIPIENT", "REPLICATE_AGE_IDENTITY",
			"REPLICATE_REQUIRE_ENCRYPTION", "REPLICATE_INTERVAL",
		} {
			t.Setenv(k, "")
		}
	}

	t.Run("disabled when no endpoint", func(t *testing.T) {
		clearReplEnv(t)
		_, enabled, err := buildReplicatorConfig("node")
		if err != nil || enabled {
			t.Fatalf("no-endpoint = (enabled=%v, err=%v), want (false, nil)", enabled, err)
		}
	})

	t.Run("age recipient + identity are wired (the plaintext-leak fix)", func(t *testing.T) {
		clearReplEnv(t)
		t.Setenv("REPLICATE_S3_ENDPOINT", "http://s3.hanzo.svc:9000")
		t.Setenv("REPLICATE_S3_ACCESS_KEY_ID", "ak")
		t.Setenv("REPLICATE_S3_SECRET_ACCESS_KEY", "sk")
		t.Setenv("REPLICATE_AGE_RECIPIENT", recipient)
		t.Setenv("REPLICATE_AGE_IDENTITY", identity)
		cfg, enabled, err := buildReplicatorConfig("kms-luxfi-0")
		if err != nil || !enabled {
			t.Fatalf("configured = (enabled=%v, err=%v), want (true,nil)", enabled, err)
		}
		if cfg.AgeRecipient == nil {
			t.Error("AgeRecipient is nil — backups would go to S3 in the CLEAR (the bug this fixes)")
		}
		if cfg.AgeIdentity == nil {
			t.Error("AgeIdentity is nil — a follower could not decrypt to Restore")
		}
		if cfg.Endpoint != "s3.hanzo.svc:9000" || cfg.UseSSL {
			t.Errorf("endpoint normalize = %q ssl=%v, want s3.hanzo.svc:9000 ssl=false", cfg.Endpoint, cfg.UseSSL)
		}
		if cfg.Path != "kms/kms-luxfi-0" {
			t.Errorf("default path = %q, want kms/kms-luxfi-0", cfg.Path)
		}
	})

	t.Run("require-encryption without a recipient is FATAL (no silent plaintext push)", func(t *testing.T) {
		clearReplEnv(t)
		t.Setenv("REPLICATE_S3_ENDPOINT", "http://s3.hanzo.svc:9000")
		t.Setenv("REPLICATE_REQUIRE_ENCRYPTION", "true")
		_, _, err := buildReplicatorConfig("node")
		if err == nil {
			t.Fatal("expected error when require-encryption is set but no recipient — got nil (would leak plaintext)")
		}
	})

	t.Run("invalid recipient is rejected", func(t *testing.T) {
		clearReplEnv(t)
		t.Setenv("REPLICATE_S3_ENDPOINT", "http://s3.hanzo.svc:9000")
		t.Setenv("REPLICATE_AGE_RECIPIENT", "not-an-age-key")
		if _, _, err := buildReplicatorConfig("node"); err == nil {
			t.Fatal("expected error for malformed age recipient")
		}
	})
}

// --- durability + replication mechanism (hermetic, no S3) --------------------

// TestSnapshotRestoreConvergence proves the AUTHORITATIVE durability +
// promote guarantee the HA design rests on: restoring the latest full
// snapshot (db.Backup(0)) into a FRESH standby reproduces the primary's
// live state EXACTLY — creates, updates, AND deletes all converge, with
// no ghosts. This is what a fresh follower boot, a catastrophic-loss
// recovery, and a clean promote-rebuild all do. No S3 dependency.
//
// Restoring into a FRESH db (not merging into an existing one) is what
// makes deletes converge without relying on incremental tombstones: a
// deleted secret is simply absent from Backup(0), so it is absent on the
// rebuilt standby. The kms-luxfi promote runbook wipes + rebuilds for
// exactly this reason.
func TestSnapshotRestoreConvergence(t *testing.T) {
	primary := openTestDB(t, filepath.Join(t.TempDir(), "primary"))
	ps := store.NewSecretStore(primary)

	putSecret(t, ps, "/orgs/hanzo", "DATABASE_URL", "default", "postgres://a")
	putSecret(t, ps, "/orgs/hanzo", "API_KEY", "default", "sk-original")

	// Mutate the primary: rotate one secret, add one, DELETE (revoke) one.
	putSecret(t, ps, "/orgs/hanzo", "API_KEY", "default", "sk-rotated")
	putSecret(t, ps, "/orgs/hanzo", "NEW_TOKEN", "default", "tok-123")
	if err := ps.Delete("/orgs/hanzo", "DATABASE_URL", "default"); err != nil {
		t.Fatalf("primary delete DATABASE_URL: %v", err)
	}

	// Full snapshot of the CURRENT live state, then restore into a fresh standby.
	var snap bytes.Buffer
	if _, err := primary.Backup(&snap, 0); err != nil {
		t.Fatalf("primary snapshot backup: %v", err)
	}
	follower := openTestDB(t, filepath.Join(t.TempDir(), "follower"))
	fs := store.NewSecretStore(follower)
	if err := follower.Load(bytes.NewReader(snap.Bytes()), 16); err != nil {
		t.Fatalf("follower load snapshot: %v", err)
	}

	if v, ok := getSecret(t, fs, "/orgs/hanzo", "API_KEY", "default"); !ok || v != "sk-rotated" {
		t.Errorf("rebuilt standby API_KEY = %q (ok=%v), want sk-rotated (update converges)", v, ok)
	}
	if v, ok := getSecret(t, fs, "/orgs/hanzo", "NEW_TOKEN", "default"); !ok || v != "tok-123" {
		t.Errorf("rebuilt standby NEW_TOKEN = %q (ok=%v), want tok-123 (create converges)", v, ok)
	}
	if v, ok := getSecret(t, fs, "/orgs/hanzo", "DATABASE_URL", "default"); ok {
		t.Errorf("rebuilt standby still serves DELETED DATABASE_URL = %q — revocation must not ghost", v)
	}
}

// TestReplicatorIncrementalOffByOne codifies a durability bug FOUND in the
// upstream ZapDB Replicator (github.com/luxfi/zapdb v1.10.0). It is a
// characterization test: it documents the exact broken behaviour so the
// mitigation (short snapshot interval as the durability floor) is anchored
// in code, and so a future zapdb bump that FIXES it flips this test and
// forces us to revisit the workaround.
//
// The bug: db.Backup(w, since) emits versions STRICTLY GREATER than
// `since`, but Incremental/Snapshot advance the cursor as
// `sinceVersion = maxVersion + 1`. So the write at exactly maxVersion+1 is
// skipped by the next incremental (empty backup) until a full Backup(0)
// snapshot re-captures it. Correct upstream fix: `sinceVersion = maxVersion`.
func TestReplicatorIncrementalOffByOne(t *testing.T) {
	db := openTestDB(t, filepath.Join(t.TempDir(), "db"))
	s := store.NewSecretStore(db)
	putSecret(t, s, "/o", "K", "default", "v1")

	var snap bytes.Buffer
	maxV, err := db.Backup(&snap, 0)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	putSecret(t, s, "/o", "K", "default", "v2") // the write at exactly maxV+1

	// Oracle: Load a backup into a follower pre-seeded with the snapshot
	// (v1), then read K. The store is encrypted at rest, so we assert on the
	// decrypted Get result — never on raw backup bytes.
	loadOnSnapshot := func(t *testing.T, extra *bytes.Buffer) string {
		t.Helper()
		f := openTestDB(t, filepath.Join(t.TempDir(), t.Name()))
		if err := f.Load(bytes.NewReader(snap.Bytes()), 16); err != nil {
			t.Fatalf("load base snapshot: %v", err)
		}
		if extra != nil {
			if err := f.Load(bytes.NewReader(extra.Bytes()), 16); err != nil {
				t.Fatalf("load incremental: %v", err)
			}
		}
		v, _ := getSecret(t, store.NewSecretStore(f), "/o", "K", "default")
		return v
	}

	// What the Replicator does: Backup(sinceVersion) with sinceVersion = maxV+1.
	var incBuggy bytes.Buffer
	if _, err := db.Backup(&incBuggy, maxV+1); err != nil {
		t.Fatalf("incremental (buggy cursor): %v", err)
	}
	if got := loadOnSnapshot(t, &incBuggy); got != "v1" {
		t.Errorf("upstream zapdb appears FIXED: Backup(maxV+1) captured the maxV+1 write (follower K=%q); "+
			"revisit the snapshot-floor workaround and adopt sinceVersion=maxVersion", got)
	}

	// The correct cursor (maxV) DOES capture it — proves the one-line fix.
	var incFixed bytes.Buffer
	if _, err := db.Backup(&incFixed, maxV); err != nil {
		t.Fatalf("incremental (correct cursor): %v", err)
	}
	if got := loadOnSnapshot(t, &incFixed); got != "v2" {
		t.Errorf("Backup(maxV) should capture the maxV+1 write, follower K=%q, want v2", got)
	}

	// A FULL snapshot always captures it — the durability floor kms-luxfi relies on.
	var snap2 bytes.Buffer
	if _, err := db.Backup(&snap2, 0); err != nil {
		t.Fatalf("snapshot2: %v", err)
	}
	fresh := openTestDB(t, filepath.Join(t.TempDir(), "fresh"))
	if err := fresh.Load(bytes.NewReader(snap2.Bytes()), 16); err != nil {
		t.Fatalf("load snapshot2: %v", err)
	}
	if v, _ := getSecret(t, store.NewSecretStore(fresh), "/o", "K", "default"); v != "v2" {
		t.Errorf("full Backup(0) must always capture the latest write; fresh follower K=%q, want v2", v)
	}
}

// TestAgeBackupRoundTrip proves the confidentiality leg: a backup
// age-encrypted with the recipient is decryptable with the identity and
// then Loads into a standby. This is the crypto path the Replicator runs
// around the S3 transport (encrypt → PutObject → GetObject → decrypt →
// Load), proving an age-wrapped S3 object restores correctly.
func TestAgeBackupRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	primary := openTestDB(t, filepath.Join(t.TempDir(), "primary"))
	ps := store.NewSecretStore(primary)
	putSecret(t, ps, "/orgs/hanzo", "SIGNING_KEY", "prod", "top-secret-value")

	var plain bytes.Buffer
	if _, err := primary.Backup(&plain, 0); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Encrypt with the recipient (what the PRIMARY does before upload).
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, id.Recipient())
	if err != nil {
		t.Fatalf("age encrypt: %v", err)
	}
	if _, err := w.Write(plain.Bytes()); err != nil {
		t.Fatalf("write ct: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close ct: %v", err)
	}
	// The ciphertext must not contain the plaintext secret value.
	if bytes.Contains(ct.Bytes(), []byte("top-secret-value")) {
		t.Fatal("age ciphertext leaks the plaintext secret value")
	}

	// Decrypt with the identity (what a FOLLOWER does on Restore).
	pr, err := age.Decrypt(bytes.NewReader(ct.Bytes()), id)
	if err != nil {
		t.Fatalf("age decrypt: %v", err)
	}
	var restored bytes.Buffer
	if _, err := restored.ReadFrom(pr); err != nil {
		t.Fatalf("read decrypted: %v", err)
	}

	follower := openTestDB(t, filepath.Join(t.TempDir(), "follower"))
	fs := store.NewSecretStore(follower)
	if err := follower.Load(bytes.NewReader(restored.Bytes()), 16); err != nil {
		t.Fatalf("follower load decrypted backup: %v", err)
	}
	if v, ok := getSecret(t, fs, "/orgs/hanzo", "SIGNING_KEY", "prod"); !ok || v != "top-secret-value" {
		t.Fatalf("follower SIGNING_KEY = %q (ok=%v), want top-secret-value", v, ok)
	}
}

// --- dbIsEmpty gate ----------------------------------------------------------

func TestDBIsEmpty(t *testing.T) {
	db := openTestDB(t, filepath.Join(t.TempDir(), "db"))
	if !dbIsEmpty(db) {
		t.Fatal("fresh store should be empty")
	}
	putSecret(t, store.NewSecretStore(db), "/orgs/hanzo", "X", "default", "1")
	if dbIsEmpty(db) {
		t.Fatal("store with one secret should not be empty")
	}
}

// --- follower read-only middleware ------------------------------------------

func TestFollowerReadOnlyMiddleware(t *testing.T) {
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	do := func(role replicaRole, method, path string) (int, bool) {
		nextCalled = false
		h := followerReadOnly(role, next)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code, nextCalled
	}

	t.Run("follower blocks writes to secrets", func(t *testing.T) {
		for _, m := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete} {
			code, called := do(roleFollower, m, "/v1/kms/orgs/hanzo/secrets/DB")
			if code != http.StatusServiceUnavailable || called {
				t.Errorf("follower %s secrets = (code=%d called=%v), want (503,false)", m, code, called)
			}
		}
	})

	t.Run("follower allows reads", func(t *testing.T) {
		code, called := do(roleFollower, http.MethodGet, "/v1/kms/orgs/hanzo/secrets/DB")
		if code != http.StatusOK || !called {
			t.Errorf("follower GET = (code=%d called=%v), want (200,true)", code, called)
		}
	})

	t.Run("follower allows the login broker (read-only exchange with IAM)", func(t *testing.T) {
		code, called := do(roleFollower, http.MethodPost, "/v1/kms/auth/login")
		if code != http.StatusOK || !called {
			t.Errorf("follower login = (code=%d called=%v), want (200,true)", code, called)
		}
	})

	t.Run("primary is a pass-through (single-node unchanged)", func(t *testing.T) {
		code, called := do(rolePrimary, http.MethodPost, "/v1/kms/orgs/hanzo/secrets")
		if code != http.StatusOK || !called {
			t.Errorf("primary POST = (code=%d called=%v), want (200,true)", code, called)
		}
	})
}

// --- opt-in real-S3 integration (skipped unless KMS_TEST_S3_ENDPOINT set) ----

// TestS3ReplicationRoundTrip_Integration drives the FULL Replicator
// (primary push → S3 → follower Restore) against a real S3 endpoint. It is
// skipped by default so CI stays hermetic; Red / the operator runs it
// against the in-cluster Hanzo S3 to prove the live path:
//
//	KMS_TEST_S3_ENDPOINT=http://s3.hanzo.svc:9000 \
//	KMS_TEST_S3_ACCESS_KEY=... KMS_TEST_S3_SECRET_KEY=... \
//	KMS_TEST_S3_BUCKET=hanzo-kms-backups \
//	go test ./... -run TestS3ReplicationRoundTrip_Integration -v
func TestS3ReplicationRoundTrip_Integration(t *testing.T) {
	endpoint := os.Getenv("KMS_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set KMS_TEST_S3_ENDPOINT (+ KMS_TEST_S3_ACCESS_KEY/SECRET_KEY/BUCKET) to run the real-S3 round-trip")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("age identity: %v", err)
	}
	host, useSSL := normalizeS3Endpoint(endpoint)
	base := badger.ReplicatorConfig{
		Endpoint:     host,
		Bucket:       envOr("KMS_TEST_S3_BUCKET", "hanzo-kms-backups"),
		Region:       envOr("KMS_TEST_S3_REGION", "us-east-1"),
		AccessKey:    os.Getenv("KMS_TEST_S3_ACCESS_KEY"),
		SecretKey:    os.Getenv("KMS_TEST_S3_SECRET_KEY"),
		UseSSL:       useSSL,
		Path:         "kms-test/" + t.Name(),
		AgeRecipient: id.Recipient(),
		AgeIdentity:  id,
	}

	primary := openTestDB(t, filepath.Join(t.TempDir(), "primary"))
	putSecret(t, store.NewSecretStore(primary), "/orgs/hanzo", "ROUNDTRIP", "prod", "value-42")

	pr, err := badger.NewReplicator(primary, base)
	if err != nil {
		t.Fatalf("primary replicator: %v", err)
	}
	if err := pr.Snapshot(context.Background()); err != nil {
		t.Fatalf("primary snapshot push: %v", err)
	}

	follower := openTestDB(t, filepath.Join(t.TempDir(), "follower"))
	fr, err := badger.NewReplicator(follower, base)
	if err != nil {
		t.Fatalf("follower replicator: %v", err)
	}
	if err := fr.Restore(context.Background()); err != nil {
		t.Fatalf("follower restore: %v", err)
	}
	if v, ok := getSecret(t, store.NewSecretStore(follower), "/orgs/hanzo", "ROUNDTRIP", "prod"); !ok || v != "value-42" {
		t.Fatalf("follower ROUNDTRIP = %q (ok=%v), want value-42", v, ok)
	}
}
