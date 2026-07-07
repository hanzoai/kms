// replication.go — durable + HA topology for the standalone Hanzo KMS
// (kms-luxfi StatefulSet). It layers three things onto the ZapDB store
// that embed.go opens, WITHOUT changing single-node behaviour:
//
//  1. ROLE. A node is a `primary` (the single writer) or a `follower`
//     (a hot standby). The role is derived from the pod ordinal so the
//     StatefulSet pod template needs no per-pod config. A lone kmsd (no
//     KMS_HA) is always primary — identical to the pre-HA daemon.
//
//  2. REPLICATION. ZapDB ships a log-shipping Replicator: the primary
//     PUSHES age-encrypted incremental backups to S3 every Interval; a
//     follower PULLS them (Restore) on a loop to stay current. Exactly
//     one node pushes a given S3 Path at a time — two would interleave
//     the inc/<version> keyspace and corrupt the log. The StatefulSet's
//     at-most-one-pod-per-ordinal invariant guarantees this structurally
//     (never by luck): only one ordinal is ever the primary.
//
//     This file also FIXES a latent confidentiality bug: the previous
//     startReplicator logged "age encryption enabled" but never populated
//     AgeRecipient/AgeIdentity, so backups went to S3 in the CLEAR. For
//     the standalone kmsd the stored value IS the logical secret (ZapDB
//     block-encrypts at rest, but db.Backup exports the DECRYPTED logical
//     KV), so an unencrypted S3 object leaks secret VALUES — not just
//     names. Age is now wired, and REPLICATE_REQUIRE_ENCRYPTION=true makes
//     a missing recipient FATAL rather than a silent plaintext push.
//
//  3. FAIL-CLOSED WRITES ON A FOLLOWER. A standby serves reads but
//     refuses mutating HTTP verbs (503), so it can never write divergent
//     state or race the primary's log even if a caller reaches its pod
//     directly (bypassing the write Service).
package kms

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/luxfi/age"
	"github.com/luxfi/log"
	badger "github.com/luxfi/zapdb"
)

// replicaRole is the HA role of this KMS node.
type replicaRole int

const (
	rolePrimary replicaRole = iota
	roleFollower
)

func (r replicaRole) String() string {
	if r == roleFollower {
		return "follower"
	}
	return "primary"
}

func (r replicaRole) isFollower() bool { return r == roleFollower }

// resolveRole determines this node's HA role. Precedence, highest first:
//
//  1. KMS_REPLICA_ROLE=primary|follower — an explicit override, used by
//     the promote runbook to pin a role irrespective of ordinal.
//  2. KMS_HA=true — derive from the pod ordinal: the ordinal equal to
//     KMS_PRIMARY_ORDINAL (default 0) is primary; every other ordinal is
//     a follower. The ordinal is parsed from POD_NAME (K8s downward API)
//     or the OS hostname (a StatefulSet sets it to the pod name). A name
//     with no numeric suffix defaults to primary (single node).
//  3. Neither set — primary. The pre-HA default: a lone kmsd is always
//     the writer, so existing single-node deploys are unchanged.
func resolveRole() replicaRole {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("KMS_REPLICA_ROLE"))) {
	case "follower", "standby", "replica":
		return roleFollower
	case "primary", "writer", "leader":
		return rolePrimary
	}
	if !boolEnv("KMS_HA") {
		return rolePrimary
	}
	primaryOrd := 0
	if v := strings.TrimSpace(os.Getenv("KMS_PRIMARY_ORDINAL")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			primaryOrd = n
		}
	}
	ord, ok := podOrdinal(firstNonEmpty(os.Getenv("POD_NAME"), os.Getenv("HOSTNAME")))
	if !ok {
		return rolePrimary // no ordinal → treat as the single writer
	}
	if ord == primaryOrd {
		return rolePrimary
	}
	return roleFollower
}

// podOrdinal extracts the trailing StatefulSet ordinal from a pod name
// like "kms-luxfi-0" → 0. Returns ok=false when there is no non-negative
// integer suffix after the final '-'.
func podOrdinal(name string) (int, bool) {
	name = strings.TrimSpace(name)
	i := strings.LastIndex(name, "-")
	if i < 0 || i == len(name)-1 {
		return 0, false
	}
	n, err := strconv.Atoi(name[i+1:])
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func boolEnv(k string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// buildReplicatorConfig assembles the ZapDB Replicator config from the
// REPLICATE_S3_* / REPLICATE_AGE_* environment. enabled=false (nil error)
// means S3 replication is not configured — a lone node with a durable PVC
// is still valid, just without offsite backup. A misconfiguration that
// would leak plaintext or cannot be honoured returns an error (fatal).
func buildReplicatorConfig(nodeID string) (cfg badger.ReplicatorConfig, enabled bool, err error) {
	rawEndpoint := strings.TrimSpace(os.Getenv("REPLICATE_S3_ENDPOINT"))
	if rawEndpoint == "" {
		return badger.ReplicatorConfig{}, false, nil
	}
	endpoint, useSSL := normalizeS3Endpoint(rawEndpoint)
	cfg = badger.ReplicatorConfig{
		Endpoint: endpoint,
		Bucket:   envOr("REPLICATE_S3_BUCKET", "hanzo-kms-backups"),
		Region:   envOr("REPLICATE_S3_REGION", "us-central1"),
		AccessKey: firstNonEmpty(
			os.Getenv("REPLICATE_S3_ACCESS_KEY_ID"),
			os.Getenv("AWS_ACCESS_KEY_ID"),
			os.Getenv("REPLICATE_S3_ACCESS_KEY"),
		),
		SecretKey: firstNonEmpty(
			os.Getenv("REPLICATE_S3_SECRET_ACCESS_KEY"),
			os.Getenv("AWS_SECRET_ACCESS_KEY"),
			os.Getenv("REPLICATE_S3_SECRET_KEY"),
		),
		UseSSL:   useSSL,
		Path:     envOr("REPLICATE_S3_PATH", envOr("REPLICATE_PATH", fmt.Sprintf("kms/%s", nodeID))),
		Interval: replicationInterval(),
		// SnapshotInterval drives full Backup(0) uploads. The full snapshot
		// is the DURABILITY FLOOR and is always EXACT (it reflects every live
		// key, and a deleted key is simply absent). It does NOT depend on the
		// incremental sinceVersion cursor, so a short snapshot interval bounds
		// worst-case RPO on its own.
		//
		// UPSTREAM (luxfi/zapdb): the incremental off-by-one is FIXED as of
		// v1.10.2 — db.Backup(w, since) emits versions strictly greater than
		// `since` and the Replicator now resumes the cursor AT maxVersion
		// (was maxVersion+1), so no boundary write is dropped between
		// snapshots. kms-luxfi is pinned to v1.10.2 (go.mod). The short
		// REPLICATE_SNAPSHOT_INTERVAL is retained as defence-in-depth: it
		// keeps the exact-snapshot floor tight regardless of the incremental
		// path, and consumer reads never touch replicated state (they hit the
		// primary's authoritative PVC), so replication only bounds
		// catastrophic dual-loss RPO.
		SnapshotInterval: snapshotInterval(),
	}

	requireEnc := boolEnv("REPLICATE_REQUIRE_ENCRYPTION")
	// Backup encryption + AUTHENTICATION (MEDIUM-4). Precedence:
	//
	//  1. Explicit X25519 recipient (REPLICATE_AGE_RECIPIENT). Public-key mode:
	//     CONFIDENTIAL but NOT authenticated — anyone with the (public)
	//     recipient can forge a backup our identity will decrypt. Kept as an
	//     override for deployments that want an explicit keypair.
	//  2. Master-key-derived scrypt passphrase (default for kms-luxfi). age's
	//     scrypt mode is SYMMETRIC-authenticated: the file key is wrapped under
	//     scrypt(passphrase), so ONLY a holder of the passphrase can produce a
	//     backup our identity loads. The passphrase is derived from the master
	//     key (KMS_ENCRYPTION_KEY_B64) which an S3-write-only attacker does NOT
	//     have — so they can neither read NOR forge/substitute a backup. This
	//     is the "sign the stream with a KMS-held key" control, via age's own
	//     AEAD rather than a bolt-on MAC.
	//  3. Neither available + require-encryption → fatal (never plaintext).
	switch {
	case strings.TrimSpace(os.Getenv("REPLICATE_AGE_RECIPIENT")) != "":
		rcpt := strings.TrimSpace(os.Getenv("REPLICATE_AGE_RECIPIENT"))
		r, perr := age.ParseX25519Recipient(rcpt)
		if perr != nil {
			return badger.ReplicatorConfig{}, false, fmt.Errorf("REPLICATE_AGE_RECIPIENT invalid: %w", perr)
		}
		cfg.AgeRecipient = r
		if idn := strings.TrimSpace(os.Getenv("REPLICATE_AGE_IDENTITY")); idn != "" {
			id, perr := age.ParseX25519Identity(idn)
			if perr != nil {
				return badger.ReplicatorConfig{}, false, fmt.Errorf("REPLICATE_AGE_IDENTITY invalid: %w", perr)
			}
			cfg.AgeIdentity = id
		}
	case len(masterKeyFromEnv()) == 32:
		rr, ri, derr := deriveScryptBackupKeys(masterKeyFromEnv())
		if derr != nil {
			return badger.ReplicatorConfig{}, false, fmt.Errorf("derive authenticated backup key: %w", derr)
		}
		cfg.AgeRecipient = rr
		cfg.AgeIdentity = ri
	case requireEnc:
		return badger.ReplicatorConfig{}, false, fmt.Errorf(
			"REPLICATE_REQUIRE_ENCRYPTION=true but neither REPLICATE_AGE_RECIPIENT nor a 32-byte KMS_ENCRYPTION_KEY_B64 is set — refusing to replicate secrets to S3 unauthenticated/in the clear")
	}
	return cfg, true, nil
}

// deriveReplicationPassphrase derives the age scrypt passphrase for
// authenticated backups from the master key, domain-separated so it is
// independent of the at-rest DEK-wrapping use of the same key. A single
// HMAC-SHA256 over a fixed label is a sound KDF for one 256-bit output.
func deriveReplicationPassphrase(masterKey []byte) string {
	m := hmac.New(sha256.New, masterKey)
	m.Write([]byte("kms-luxfi/replication/age/v1"))
	return base64.RawStdEncoding.EncodeToString(m.Sum(nil))
}

// deriveScryptBackupKeys builds the age scrypt recipient/identity pair for
// authenticated S3 backups from the master key. The passphrase is full-entropy
// (a 256-bit HMAC output), so the scrypt work factor is not a brute-force
// defence here — it is kept modest (KMS_REPLICATE_SCRYPT_LOGN, default 15) to
// bound per-object CPU; scrypt runs only when an actual write is backed up.
func deriveScryptBackupKeys(masterKey []byte) (age.Recipient, age.Identity, error) {
	pass := deriveReplicationPassphrase(masterKey)
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		return nil, nil, err
	}
	r.SetWorkFactor(scryptWorkFactor())
	id, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, nil, err
	}
	return r, id, nil
}

func scryptWorkFactor() int {
	if v := strings.TrimSpace(os.Getenv("KMS_REPLICATE_SCRYPT_LOGN")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 && n <= 22 {
			return n
		}
	}
	return 15
}

func replicationInterval() time.Duration {
	if d, ok := durationEnv("REPLICATE_INTERVAL"); ok {
		return d
	}
	return time.Second
}

// snapshotInterval is the full-Backup(0) cadence — the durability floor.
// Unset preserves the ZapDB default (1h); kms-luxfi overrides it to a few
// minutes so the RPO floor is tight regardless of the incremental cursor.
func snapshotInterval() time.Duration {
	if d, ok := durationEnv("REPLICATE_SNAPSHOT_INTERVAL"); ok {
		return d
	}
	return time.Hour
}

func followerRestoreInterval() time.Duration {
	if d, ok := durationEnv("KMS_FOLLOWER_RESTORE_INTERVAL"); ok {
		return d
	}
	return 10 * time.Second
}

func durationEnv(k string) (time.Duration, bool) {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d, true
		}
	}
	return 0, false
}

// startReplication wires ZapDB replication for this node's role and
// returns the Replicator (nil when S3 replication is unconfigured) so
// Stop() can drain it. A fatal misconfiguration (e.g. require-encryption
// without a recipient) returns an error so Embed refuses to boot.
//
//	primary  — if the local store is EMPTY (fresh PVC) it first Restores
//	           from S3 to self-heal after volume loss, then starts the
//	           incremental PUSH loop. It never overwrites a non-empty
//	           store with older S3 state.
//	follower — never pushes. Runs one initial Restore to hydrate, then a
//	           Restore PULL loop on KMS_FOLLOWER_RESTORE_INTERVAL to track
//	           the primary. Reads are served from its local encrypted
//	           store; mutating verbs are refused by followerReadOnly.
func startReplication(ctx context.Context, db *badger.DB, nodeID string, role replicaRole, hydrated *atomic.Bool) (*badger.Replicator, error) {
	cfg, enabled, err := buildReplicatorConfig(nodeID)
	if err != nil {
		return nil, err
	}
	if !enabled {
		// No S3 → the local PVC is authoritative; the node is hydrated now.
		hydrated.Store(true)
		log.Info("kms.Embed: S3 replication disabled (set REPLICATE_S3_ENDPOINT to enable)", "role", role.String())
		return nil, nil
	}
	r, err := badger.NewReplicator(db, cfg)
	if err != nil {
		// Non-fatal: a node can run on its durable PVC without offsite
		// backup. Log loudly; do not crash the secret path.
		hydrated.Store(true)
		log.Warn("kms.Embed: S3 replicator init failed — replication disabled", "err", err)
		return nil, nil
	}

	switch role {
	case roleFollower:
		// MEDIUM-2: hydrate ASYNC + bounded, never blocking boot. followerLoop
		// does an immediate bounded Restore (flips hydrated on first success)
		// then keeps pulling. Readiness (/readyz) reflects hydrated; liveness
		// (/healthz) is up immediately so a slow/large S3 restore cannot
		// CrashLoop the pod.
		go followerLoop(ctx, r, hydrated)
		log.Info("kms.Embed: S3 replication started (FOLLOWER: pull/restore only, read-only)",
			"endpoint", cfg.Endpoint, "bucket", cfg.Bucket, "path", cfg.Path,
			"restore_interval", followerRestoreInterval().String(),
			"age_encrypted", cfg.AgeRecipient != nil)
	default: // rolePrimary
		if dbIsEmpty(db) {
			// Self-heal after PVC loss: restore ASYNC + bounded. The push loop
			// gates on hydrated, so we NEVER push an empty store over the S3
			// log before the restore completes.
			log.Info("kms.Embed: local store empty — hydrating from S3 before assuming primary (self-heal after PVC loss)")
			hydrateAsync(ctx, r, hydrated, "primary-bootstrap")
		} else {
			// Durable non-empty PVC is already authoritative.
			hydrated.Store(true)
		}
		// HIGH-3: writer fence. When KMS_WRITER_LEASE=true the primary may push
		// only while it holds a fresh K8s Lease, closing the different-ordinal-
		// promote-during-partition split-brain. When off, the StatefulSet
		// ordinal invariant is the sole guarantee (unchanged behaviour).
		fence, ferr := maybeWriterLease(nodeID)
		if ferr != nil {
			return nil, ferr // asked for the fence, cannot provide it → refuse to boot unfenced
		}
		if fence != nil {
			go fence.run(ctx)
		}
		// Always drive the push via primaryPushLoop (fence may be nil): it
		// gates every push on BOTH hydrated and, when set, the fence — so the
		// hydrate-before-push safety holds on the non-fenced path too.
		go primaryPushLoop(ctx, r, fence, hydrated)
		log.Info("kms.Embed: S3 replication started (PRIMARY: incremental push)",
			"endpoint", cfg.Endpoint, "bucket", cfg.Bucket, "path", cfg.Path,
			"interval", cfg.Interval.String(), "fenced", fence != nil,
			"age_encrypted", cfg.AgeRecipient != nil)
	}
	return r, nil
}

// hydrateAsync runs a bounded initial Restore in the background, retrying on
// failure, and flips hydrated true on the first success. Bounding each attempt
// (KMS_RESTORE_TIMEOUT) keeps a hung S3 from wedging the goroutine forever;
// retrying means a transient S3 blip at boot does not leave the node
// permanently un-hydrated.
func hydrateAsync(ctx context.Context, r *badger.Replicator, hydrated *atomic.Bool, label string) {
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			rctx, cancel := context.WithTimeout(ctx, restoreTimeout())
			err := r.Restore(rctx)
			cancel()
			if err == nil {
				hydrated.Store(true)
				log.Info("kms: initial hydrate complete", "role", label)
				return
			}
			log.Warn("kms: initial hydrate failed — retrying", "role", label, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(hydrateRetryInterval()):
			}
		}
	}()
}

// maybeWriterLease builds the primary's K8s Lease fence when KMS_WRITER_LEASE is
// set, else returns (nil, nil). A requested-but-unbuildable fence is a FATAL
// error: we must never run an unfenced writer once the operator has asked for
// the fence.
func maybeWriterLease(nodeID string) (*writerLease, error) {
	if !boolEnv("KMS_WRITER_LEASE") {
		return nil, nil
	}
	holder := firstNonEmpty(os.Getenv("POD_NAME"), os.Getenv("HOSTNAME"), nodeID)
	f, err := newWriterLease(holder)
	if err != nil {
		return nil, fmt.Errorf("KMS_WRITER_LEASE=true but the writer fence could not initialise (refusing to run an unfenced writer): %w", err)
	}
	return f, nil
}

// primaryPushLoop mirrors Replicator.Start's two-ticker loop but gates every
// push on the writer fence: an incremental or snapshot upload happens only while
// this node holds the Lease. The moment the fence drops (renew failure, lost
// lease), pushes stop — so a partitioned ex-primary cannot keep writing the S3
// log after a standby has been promoted.
func primaryPushLoop(ctx context.Context, r *badger.Replicator, fence *writerLease, hydrated *atomic.Bool) {
	inc := time.NewTicker(replicationInterval())
	defer inc.Stop()
	snap := time.NewTicker(snapshotInterval())
	defer snap.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-inc.C:
			if !canPush(hydrated, fence) {
				continue
			}
			if err := r.Incremental(ctx); err != nil {
				log.Warn("kms: primary incremental push failed", "err", err)
			}
		case <-snap.C:
			if !canPush(hydrated, fence) {
				continue
			}
			if err := r.Snapshot(ctx); err != nil {
				log.Warn("kms: primary snapshot push failed", "err", err)
			}
		}
	}
}

// canPush is the primary's push gate: it may push only when the store is
// hydrated (never push an un-restored/empty store over the S3 log) AND, when a
// writer fence is configured, while it holds the Lease. Both conditions
// fail-closed — a false from either stops the push.
func canPush(hydrated *atomic.Bool, fence *writerLease) bool {
	return hydrated.Load() && (fence == nil || fence.Held())
}

// restoreTimeout bounds a single initial/loop Restore so a hung S3 cannot wedge
// the hydrate/pull goroutine. Generous by default (large snapshots); override
// with KMS_RESTORE_TIMEOUT.
func restoreTimeout() time.Duration {
	if d, ok := durationEnv("KMS_RESTORE_TIMEOUT"); ok {
		return d
	}
	return 2 * time.Minute
}

// hydrateRetryInterval is the backoff between failed initial-hydrate attempts.
func hydrateRetryInterval() time.Duration {
	if d, ok := durationEnv("KMS_HYDRATE_RETRY_INTERVAL"); ok {
		return d
	}
	return 5 * time.Second
}

// followerLoop hydrates then periodically Restores from S3 so a standby stays
// current with the primary and can be promoted with a bounded RPO (≈ the
// primary push interval). The FIRST Restore is a bounded hydrate that flips
// hydrated (→ /readyz 200); subsequent Restores keep it current. Each attempt
// is timeout-bounded so a hung S3 can't wedge the loop. Exits on ctx cancel.
func followerLoop(ctx context.Context, r *badger.Replicator, hydrated *atomic.Bool) {
	restore := func() {
		rctx, cancel := context.WithTimeout(ctx, restoreTimeout())
		defer cancel()
		if err := r.Restore(rctx); err != nil {
			log.Warn("kms: follower restore failed", "err", err, "hydrated", hydrated.Load())
			return
		}
		if hydrated.CompareAndSwap(false, true) {
			log.Info("kms: follower initial hydrate complete (ready)")
		}
	}
	restore() // immediate hydrate, don't wait a full interval
	t := time.NewTicker(followerRestoreInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			restore()
		}
	}
}

// dbIsEmpty reports whether the ZapDB has no user keys yet — used to gate
// the primary's bootstrap Restore so it never overwrites a live store
// with older S3 state. Cheap: stops after the first key.
func dbIsEmpty(db *badger.DB) bool {
	empty := true
	_ = db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Rewind()
		if it.Valid() {
			empty = false
		}
		return nil
	})
	return empty
}

// followerReadOnly refuses mutating HTTP verbs on a follower (hot
// standby) so a standby can never write divergent state into its local
// store or race the primary's S3 log. GET/HEAD pass through, as does the
// auth/login broker (POST /v1/kms/auth/login is a read-only exchange with
// IAM — it writes no secret). On a primary this is a pass-through, so
// single-node/primary behaviour is unchanged.
//
// Defence in depth: the kms-luxfi write Service already routes writes to
// the primary pod only; this guard means a caller who reaches a follower
// pod directly (bypassing the Service) still cannot mutate.
func followerReadOnly(role replicaRole, next http.Handler) http.Handler {
	if !role.isFollower() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMutatingMethod(r.Method) && !isLoginPath(r.URL.Path) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"message": "read-only replica (follower): writes must target the primary (kms-luxfi-primary)",
				"role":    "follower",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isMutatingMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func isLoginPath(p string) bool { return p == "/v1/kms/auth/login" }
