/*
 * SPDX-FileCopyrightText: © 2017-2025 Istari Digital, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package badger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luxfi/age"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ReplicatorConfig configures encrypted streaming replication to S3.
type ReplicatorConfig struct {
	// S3 connection.
	Bucket    string
	Endpoint  string
	Region    string
	AccessKey string
	SecretKey string
	UseSSL    bool
	Path      string // S3 key prefix (e.g. "zapdb/node-0")

	// Encryption (optional — if nil, backups are unencrypted).
	AgeRecipient age.Recipient // age public key for encryption
	AgeIdentity  age.Identity  // age private key for decryption (restore only)

	// Timing.
	Interval         time.Duration // incremental sync interval (default 1s)
	SnapshotInterval time.Duration // full snapshot interval (default 1h)

	// Concurrency for db.Load.
	MaxPendingWrites int // default 16

	// Logging — uses the DB logger if nil.
	Logger Logger
}

func (c *ReplicatorConfig) interval() time.Duration {
	if c.Interval > 0 {
		return c.Interval
	}
	return time.Second
}

func (c *ReplicatorConfig) snapshotInterval() time.Duration {
	if c.SnapshotInterval > 0 {
		return c.SnapshotInterval
	}
	return time.Hour
}

func (c *ReplicatorConfig) maxPendingWrites() int {
	if c.MaxPendingWrites > 0 {
		return c.MaxPendingWrites
	}
	return 16
}

// Replicator continuously streams incremental backups to S3, encrypted with age.
type Replicator struct {
	db   *DB
	cfg  ReplicatorConfig
	s3   *minio.Client
	log  Logger
	mu   sync.Mutex
	stop context.CancelFunc

	sinceVersion uint64
	lastSnapshot time.Time
}

// NewReplicator creates a Replicator. Call Start to begin replication.
func NewReplicator(db *DB, cfg ReplicatorConfig) (*Replicator, error) {
	s3, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Region: cfg.Region,
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("replicate: s3 client: %w", err)
	}

	log := cfg.Logger
	if log == nil {
		log = db.opt.Logger
	}

	return &Replicator{
		db:  db,
		cfg: cfg,
		s3:  s3,
		log: log,
	}, nil
}

// Start begins the replication loop. It blocks until ctx is cancelled or Stop is called.
func (r *Replicator) Start(ctx context.Context) {
	ctx, r.stop = context.WithCancel(ctx)

	incTicker := time.NewTicker(r.cfg.interval())
	defer incTicker.Stop()

	snapTicker := time.NewTicker(r.cfg.snapshotInterval())
	defer snapTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-incTicker.C:
			if err := r.Incremental(ctx); err != nil {
				r.log.Warningf("replicate: incremental: %v", err)
			}
		case <-snapTicker.C:
			if err := r.Snapshot(ctx); err != nil {
				r.log.Warningf("replicate: snapshot: %v", err)
			}
		}
	}
}

// Stop cancels the replication loop.
func (r *Replicator) Stop() {
	if r.stop != nil {
		r.stop()
	}
}

// Incremental runs a single incremental backup. It backs up all changes since
// the last replicated version, encrypts if configured, and uploads to S3.
// Returns nil if there are no new changes.
func (r *Replicator) Incremental(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// TODO: replace bytes.Buffer with io.Pipe for streaming to avoid 3x memory overhead on large databases
	var buf bytes.Buffer
	maxVersion, err := r.db.Backup(&buf, r.sinceVersion)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if buf.Len() == 0 {
		return nil
	}

	var body io.Reader = &buf
	size := int64(buf.Len())

	if r.cfg.AgeRecipient != nil {
		encrypted, err := encrypt(&buf, r.cfg.AgeRecipient)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		body = encrypted
		size = int64(encrypted.Len())
	}

	key := r.incKey(maxVersion)
	_, err = r.s3.PutObject(ctx, r.cfg.Bucket, key, body, size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("upload %s: %w", key, err)
	}

	r.sinceVersion = maxVersion + 1
	r.log.Infof("replicate: incremental uploaded %s (%d bytes, version %d)", key, size, maxVersion)
	return nil
}

// Snapshot creates a full backup (sinceVersion=0), encrypts, and uploads to S3.
func (r *Replicator) Snapshot(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// TODO: replace bytes.Buffer with io.Pipe for streaming to avoid 3x memory overhead on large databases
	var buf bytes.Buffer
	maxVersion, err := r.db.Backup(&buf, 0)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if buf.Len() == 0 {
		return nil
	}

	var body io.Reader = &buf
	size := int64(buf.Len())

	if r.cfg.AgeRecipient != nil {
		encrypted, err := encrypt(&buf, r.cfg.AgeRecipient)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		body = encrypted
		size = int64(encrypted.Len())
	}

	key := r.snapKey(time.Now())
	_, err = r.s3.PutObject(ctx, r.cfg.Bucket, key, body, size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("upload %s: %w", key, err)
	}

	r.lastSnapshot = time.Now()
	r.sinceVersion = maxVersion + 1
	r.log.Infof("replicate: snapshot uploaded %s (%d bytes, version %d)", key, size, maxVersion)
	return nil
}

// Restore downloads the latest snapshot from S3, decrypts if needed, and loads
// into the database. Then it applies any incremental backups that are newer than
// the snapshot. The DB should not have concurrent transactions running.
func (r *Replicator) Restore(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Find latest snapshot.
	snapPrefix := path.Join(r.cfg.Path, "snap") + "/"
	latestSnap := ""
	for obj := range r.s3.ListObjects(ctx, r.cfg.Bucket, minio.ListObjectsOptions{
		Prefix:    snapPrefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return fmt.Errorf("list snapshots: %w", obj.Err)
		}
		if obj.Key > latestSnap {
			latestSnap = obj.Key
		}
	}

	var snapVersion uint64

	if latestSnap != "" {
		r.log.Infof("replicate: restoring snapshot %s", latestSnap)
		if err := r.downloadAndLoad(ctx, latestSnap); err != nil {
			return fmt.Errorf("restore snapshot: %w", err)
		}
		// Extract timestamp from snap key to filter incrementals.
		// We still apply all incrementals since we don't know the exact version
		// from the filename. The DB.Load handles duplicates safely.
	}

	// Find and apply incrementals in order.
	incPrefix := path.Join(r.cfg.Path, "inc") + "/"
	type incEntry struct {
		key     string
		version uint64
	}
	var incs []incEntry
	for obj := range r.s3.ListObjects(ctx, r.cfg.Bucket, minio.ListObjectsOptions{
		Prefix:    incPrefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return fmt.Errorf("list incrementals: %w", obj.Err)
		}
		v := versionFromKey(obj.Key)
		if v > snapVersion {
			incs = append(incs, incEntry{key: obj.Key, version: v})
		}
	}

	sort.Slice(incs, func(i, j int) bool { return incs[i].version < incs[j].version })

	for _, inc := range incs {
		r.log.Infof("replicate: applying incremental %s", inc.key)
		if err := r.downloadAndLoad(ctx, inc.key); err != nil {
			return fmt.Errorf("restore incremental %s: %w", inc.key, err)
		}
		r.sinceVersion = inc.version + 1
	}

	r.log.Infof("replicate: restore complete (sinceVersion=%d)", r.sinceVersion)
	return nil
}

func (r *Replicator) downloadAndLoad(ctx context.Context, key string) error {
	obj, err := r.s3.GetObject(ctx, r.cfg.Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return fmt.Errorf("get %s: %w", key, err)
	}
	defer obj.Close()

	var reader io.Reader = obj
	if r.cfg.AgeIdentity != nil {
		dec, err := age.Decrypt(obj, r.cfg.AgeIdentity)
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", key, err)
		}
		reader = dec
	}

	return r.db.Load(reader, r.cfg.maxPendingWrites())
}

func (r *Replicator) incKey(version uint64) string {
	ext := ".zap"
	if r.cfg.AgeRecipient != nil {
		ext = ".zap.age"
	}
	return path.Join(r.cfg.Path, "inc", fmt.Sprintf("%020d%s", version, ext))
}

func (r *Replicator) snapKey(t time.Time) string {
	ext := ".zap"
	if r.cfg.AgeRecipient != nil {
		ext = ".zap.age"
	}
	return path.Join(r.cfg.Path, "snap", fmt.Sprintf("%d%s", t.UnixNano(), ext))
}

// versionFromKey extracts the version number from an incremental backup key.
func versionFromKey(key string) uint64 {
	base := path.Base(key)
	// Strip extensions (.zap, .zap.age)
	base = strings.TrimSuffix(base, ".age")
	base = strings.TrimSuffix(base, ".zap")
	v, _ := strconv.ParseUint(base, 10, 64)
	return v
}

// encrypt pipes plaintext through age encryption and returns the ciphertext buffer.
func encrypt(plaintext io.Reader, recipient age.Recipient) (*bytes.Buffer, error) {
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(w, plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return &out, nil
}
