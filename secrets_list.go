// Metadata-only secret listing (R-LIST) + wall-clock mtime tracking.
//
// This file owns the read-only "browse an org's secret KEYS" surface that
// the operator console needs. It is, by construction, incapable of returning
// a secret value:
//
//   - The scan iterates ZapDB KEYS ONLY (PrefetchValues=false). The encrypted
//     value blob under kms/secrets/{path}/{env}/{name} is never read from the
//     LSM into the handler. There is no code path from this file to a value.
//   - The row type (secretMetaRow) has no value/ciphertext field, so even a
//     future careless edit cannot serialize a value.
//
// What IS listable, verified against the actual store (github.com/luxfi/kms
// pkg/store): secret path/name/env are stored in PLAINTEXT as the ZapDB key
// `kms/secrets/{path}/{env}/{name}`. Only the value blob is protected (ZapDB
// at-rest encryption). So names/paths are honestly enumerable metadata; the
// value is not, and is never touched here.
//
// Two sibling-key families parallel the secret records, mirroring the
// versioning.go pattern (no upstream schema change):
//
//	kms/versions/{path}/{env}/{name}  → monotonic int64 (versioning.go)
//	kms/mtimes/{path}/{env}/{name}    → wall-clock UnixNano int64 (this file)
//
// updatedTime is sourced from kms/mtimes — NOT from the value blob (whose
// UpdatedAt the Hanzo write path never set) and NOT from ZapDB's commit
// counter (a logical version, not wall-clock). A record written before this
// change carries no mtime row and is reported with updatedTime omitted —
// honestly "unknown", never faked.
package kms

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	badger "github.com/luxfi/zapdb"
)

// maxListRows caps a single metadata listing so a pathological namespace
// cannot exhaust server memory or produce an unbounded response. The scan is
// keys-only and cheap, but the response is still bounded. A metadata row is a
// few hundred bytes, so 10k rows is well under a MiB.
const maxListRows = 10000

// secretMetaRow is one row of the metadata listing. It deliberately has NO
// value/ciphertext field — the list endpoint is structurally incapable of
// emitting a secret value.
type secretMetaRow struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	Env         string `json:"env"`
	Version     int64  `json:"version"`
	UpdatedTime string `json:"updatedTime,omitempty"` // RFC3339; omitted when unknown
}

// listSecretMetadata returns metadata rows for every secret whose key falls
// under kms/secrets/<listPath>/, optionally filtered to envFilter. listPath
// carries no trailing slash; the boundary slash is appended here so a prefix
// of "brand/hanzo" matches "brand/hanzo/..." but never "brand/hanzofoo/...".
// It NEVER reads a secret value: phase 1 iterates keys only; phase 2 reads the
// version and mtime sibling counters (not the value). Returns (rows, truncated).
func listSecretMetadata(db *badger.DB, listPath, envFilter string) (rows []secretMetaRow, truncated bool) {
	// Mirror store.secretKey's layout: kms/secrets/{path}/{env}/{name}.
	dbPrefix := []byte("kms/secrets/" + listPath + "/")

	type ref struct{ path, name, env string }
	var refs []ref

	_ = db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false // KEYS ONLY — the value blob is never loaded.
		opts.Prefix = dbPrefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			// KeyCopy: Item.Key() is only valid for the current iteration step.
			key := string(it.Item().KeyCopy(nil))
			rel := strings.TrimPrefix(key, "kms/secrets/")
			p, e, n, ok := parseSecretRelKey(rel)
			if !ok {
				continue
			}
			if envFilter != "" && e != envFilter {
				continue
			}
			if len(refs) >= maxListRows {
				truncated = true
				break
			}
			refs = append(refs, ref{path: p, name: n, env: e})
		}
		return nil
	})

	// Phase 2: enrich with version + mtime (sibling counters, NOT the value).
	rows = make([]secretMetaRow, 0, len(refs))
	for _, rf := range refs {
		ver, _ := readVersion(db, rf.path, rf.name, rf.env)
		row := secretMetaRow{Path: rf.path, Name: rf.name, Env: rf.env, Version: ver}
		if ns, _ := readMtime(db, rf.path, rf.name, rf.env); ns > 0 {
			row.UpdatedTime = time.Unix(0, ns).UTC().Format(time.RFC3339)
		}
		rows = append(rows, row)
	}
	return rows, truncated
}

// parseSecretRelKey inverts store.secretKey's "{path}/{env}/{name}" layout
// (the portion after the kms/secrets/ prefix). name is the final segment,
// env the penultimate, path everything before. Returns ok=false for any key
// that does not carry a full path/env/name triple.
func parseSecretRelKey(rel string) (path, env, name string, ok bool) {
	ls := strings.LastIndex(rel, "/")
	if ls < 0 {
		return "", "", "", false
	}
	name = rel[ls+1:]
	head := rel[:ls] // {path}/{env}
	es := strings.LastIndex(head, "/")
	if es < 0 {
		return "", "", "", false
	}
	env = head[es+1:]
	path = head[:es]
	if path == "" || env == "" || name == "" {
		return "", "", "", false
	}
	return path, env, name, true
}

// --- mtime sibling index (parallel to versioning.go) ---

// mtimeKey returns the ZapDB key for a secret's wall-clock update time.
// Kept parallel to store.secretKey / versionKey so a prefix scan still works.
func mtimeKey(path, name, env string) []byte {
	return []byte(fmt.Sprintf("kms/mtimes/%s/%s/%s", path, env, name))
}

// writeMtime records the current wall-clock time (UnixNano, big-endian int64)
// for a secret. Called from the write handlers after a successful Put. Best
// effort: a failure is logged by the caller, never fatal to the write.
func writeMtime(db *badger.DB, path, name, env string) error {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(time.Now().UnixNano()))
	return db.Update(func(txn *badger.Txn) error {
		return txn.Set(mtimeKey(path, name, env), buf)
	})
}

// readMtime returns the recorded UnixNano update time, or 0 if none was
// recorded (the secret predates mtime tracking — honestly "unknown").
func readMtime(db *badger.DB, path, name, env string) (int64, error) {
	var ns int64
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(mtimeKey(path, name, env))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil // ns stays 0
		}
		if err != nil {
			return err
		}
		return item.Value(func(b []byte) error {
			if len(b) != 8 {
				return fmt.Errorf("kms: malformed mtime record (len=%d)", len(b))
			}
			ns = int64(binary.BigEndian.Uint64(b))
			return nil
		})
	})
	return ns, err
}

// deleteMtime removes the mtime record when a secret is deleted, so a later
// re-create does not surface a stale update time.
func deleteMtime(db *badger.DB, path, name, env string) error {
	return db.Update(func(txn *badger.Txn) error {
		err := txn.Delete(mtimeKey(path, name, env))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		return err
	})
}
