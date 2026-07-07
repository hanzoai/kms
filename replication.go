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
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
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
		// is the DURABILITY FLOOR and is always EXACT (it reflects every
		// live key, and a deleted key is simply absent). It does NOT depend
		// on the incremental sinceVersion cursor — see the note below — so a
		// short snapshot interval bounds worst-case RPO independently of the
		// upstream Replicator's incremental off-by-one.
		//
		// UPSTREAM NOTE (luxfi/zapdb v1.10.0 replicate.go): db.Backup(w,
		// since) emits versions STRICTLY GREATER than `since`, but both
		// Incremental and Snapshot advance the cursor as
		// `sinceVersion = maxVersion + 1`. The write landing exactly at
		// maxVersion+1 is therefore skipped by INCREMENTALS until the next
		// full snapshot re-captures it via Backup(0). kms-luxfi sets a short
		// REPLICATE_SNAPSHOT_INTERVAL so that floor is minutes, not the 1h
		// default; consumer reads never touch replicated state (they hit the
		// primary's authoritative PVC), so this only bounds catastrophic-
		// dual-loss RPO. The one-line upstream fix is `sinceVersion =
		// maxVersion` (make Backup's `since` inclusive-consistent).
		SnapshotInterval: snapshotInterval(),
	}

	requireEnc := boolEnv("REPLICATE_REQUIRE_ENCRYPTION")
	if rcpt := strings.TrimSpace(os.Getenv("REPLICATE_AGE_RECIPIENT")); rcpt != "" {
		r, perr := age.ParseX25519Recipient(rcpt)
		if perr != nil {
			return badger.ReplicatorConfig{}, false, fmt.Errorf("REPLICATE_AGE_RECIPIENT invalid: %w", perr)
		}
		cfg.AgeRecipient = r
	} else if requireEnc {
		return badger.ReplicatorConfig{}, false, fmt.Errorf(
			"REPLICATE_REQUIRE_ENCRYPTION=true but REPLICATE_AGE_RECIPIENT is empty — refusing to replicate secrets to S3 in the clear")
	}
	if idn := strings.TrimSpace(os.Getenv("REPLICATE_AGE_IDENTITY")); idn != "" {
		id, perr := age.ParseX25519Identity(idn)
		if perr != nil {
			return badger.ReplicatorConfig{}, false, fmt.Errorf("REPLICATE_AGE_IDENTITY invalid: %w", perr)
		}
		cfg.AgeIdentity = id
	}
	return cfg, true, nil
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
func startReplication(ctx context.Context, db *badger.DB, nodeID string, role replicaRole) (*badger.Replicator, error) {
	cfg, enabled, err := buildReplicatorConfig(nodeID)
	if err != nil {
		return nil, err
	}
	if !enabled {
		log.Info("kms.Embed: S3 replication disabled (set REPLICATE_S3_ENDPOINT to enable)", "role", role.String())
		return nil, nil
	}
	r, err := badger.NewReplicator(db, cfg)
	if err != nil {
		// Non-fatal: a node can run on its durable PVC without offsite
		// backup. Log loudly; do not crash the secret path.
		log.Warn("kms.Embed: S3 replicator init failed — replication disabled", "err", err)
		return nil, nil
	}

	switch role {
	case roleFollower:
		// Hydrate before serving, best-effort. A brand-new follower with
		// an empty S3 log simply starts empty and catches up on the loop.
		if rerr := r.Restore(ctx); rerr != nil {
			log.Warn("kms.Embed: follower initial restore failed (will retry on loop)", "err", rerr)
		}
		go followerLoop(ctx, r)
		log.Info("kms.Embed: S3 replication started (FOLLOWER: pull/restore only, read-only)",
			"endpoint", cfg.Endpoint, "bucket", cfg.Bucket, "path", cfg.Path,
			"restore_interval", followerRestoreInterval().String(),
			"age_encrypted", cfg.AgeRecipient != nil)
	default: // rolePrimary
		if dbIsEmpty(db) {
			log.Info("kms.Embed: local store empty — restoring from S3 before assuming primary (self-heal after PVC loss)")
			if rerr := r.Restore(ctx); rerr != nil {
				log.Warn("kms.Embed: primary bootstrap restore failed (starting empty)", "err", rerr)
			}
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
			go primaryPushLoop(ctx, r, fence)
			log.Info("kms.Embed: S3 replication started (PRIMARY: FENCED incremental push)",
				"endpoint", cfg.Endpoint, "bucket", cfg.Bucket, "path", cfg.Path,
				"interval", cfg.Interval.String(), "lease", envOr("KMS_WRITER_LEASE_NAME", "kms-luxfi-writer"),
				"age_encrypted", cfg.AgeRecipient != nil)
		} else {
			go r.Start(ctx)
			log.Info("kms.Embed: S3 replication started (PRIMARY: incremental push)",
				"endpoint", cfg.Endpoint, "bucket", cfg.Bucket, "path", cfg.Path,
				"interval", cfg.Interval.String(),
				"age_encrypted", cfg.AgeRecipient != nil)
		}
	}
	return r, nil
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
func primaryPushLoop(ctx context.Context, r *badger.Replicator, fence *writerLease) {
	inc := time.NewTicker(replicationInterval())
	defer inc.Stop()
	snap := time.NewTicker(snapshotInterval())
	defer snap.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-inc.C:
			if !fence.Held() {
				continue
			}
			if err := r.Incremental(ctx); err != nil {
				log.Warn("kms: primary incremental push failed", "err", err)
			}
		case <-snap.C:
			if !fence.Held() {
				continue
			}
			if err := r.Snapshot(ctx); err != nil {
				log.Warn("kms: primary snapshot push failed", "err", err)
			}
		}
	}
}

// followerLoop periodically Restores from S3 so a standby stays current
// with the primary and can be promoted with a bounded RPO (≈ the primary
// push interval). Exits when ctx is cancelled (graceful shutdown).
func followerLoop(ctx context.Context, r *badger.Replicator) {
	t := time.NewTicker(followerRestoreInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Restore(ctx); err != nil {
				log.Warn("kms: follower restore failed", "err", err)
			}
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
