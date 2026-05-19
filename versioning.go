// Package main — secret version tracking for replay protection (R-3).
//
// The upstream luxfi/kms store.Secret has no version field. We store a
// monotonic int64 version alongside each secret in ZapDB under a sibling
// key prefix `kms/versions/{path}/{env}/{name}` so upstream schema stays
// untouched — no fork, no PR, no schema migration.
//
// Threat model (R-3): a captured Update envelope replayed after a
// subsequent rotation would overwrite a live secret with a stale value
// (revert-on-replay). Create is safe to replay because POST is an upsert
// of the new value; an adversary cannot use it to revert.
//
// Fix: Update (PATCH) requires the caller to supply the secret's current
// version (If-Match header or JSON body `version`). Mismatch → 409. Each
// successful write increments the stored version. Create (POST) seeds
// version = 1 on insert and bumps version on upsert — idempotent semantics
// preserved (no information leak; adversary cannot cause revert because
// PATCH is the only mutate-with-prior path and it requires version).
package kms

import (
	"encoding/binary"
	"errors"
	"fmt"

	badger "github.com/luxfi/zapdb"
)

// ErrVersionMismatch is returned from storePutWithVersion when the caller
// supplies a version that does not match the current on-disk version.
var ErrVersionMismatch = errors.New("kms: version mismatch")

// versionKey returns the ZapDB key used to store the monotonic version
// counter for a (path, name, env) secret. Kept parallel to the store's
// own layout so a list/scan by prefix still works.
func versionKey(path, name, env string) []byte {
	return []byte(fmt.Sprintf("kms/versions/%s/%s/%s", path, env, name))
}

// readVersion returns the current version of a secret, or 0 if no version
// has been recorded (equivalent to "secret does not exist yet").
func readVersion(db *badger.DB, path, name, env string) (int64, error) {
	var v int64
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(versionKey(path, name, env))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil // v stays 0
		}
		if err != nil {
			return err
		}
		return item.Value(func(buf []byte) error {
			if len(buf) != 8 {
				return fmt.Errorf("kms: malformed version record (len=%d)", len(buf))
			}
			v = int64(binary.BigEndian.Uint64(buf))
			return nil
		})
	})
	return v, err
}

// bumpVersion atomically reads-then-writes the version counter, returning
// the NEW version written. Requires the caller-supplied expected version
// to match the current version. If expected is -1, skip the CAS check
// (used by POST/upsert; POST does not claim to know the prior version).
func bumpVersion(db *badger.DB, path, name, env string, expected int64) (int64, error) {
	var newVer int64
	err := db.Update(func(txn *badger.Txn) error {
		var cur int64
		item, err := txn.Get(versionKey(path, name, env))
		switch {
		case errors.Is(err, badger.ErrKeyNotFound):
			cur = 0
		case err != nil:
			return err
		default:
			if valErr := item.Value(func(buf []byte) error {
				if len(buf) != 8 {
					return fmt.Errorf("kms: malformed version record (len=%d)", len(buf))
				}
				cur = int64(binary.BigEndian.Uint64(buf))
				return nil
			}); valErr != nil {
				return valErr
			}
		}
		if expected >= 0 && expected != cur {
			return ErrVersionMismatch
		}
		newVer = cur + 1
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(newVer))
		return txn.Set(versionKey(path, name, env), buf)
	})
	return newVer, err
}

// deleteVersion removes the version record when a secret is deleted, so
// that a later re-create starts from version 1 again (not version N+1).
func deleteVersion(db *badger.DB, path, name, env string) error {
	return db.Update(func(txn *badger.Txn) error {
		err := txn.Delete(versionKey(path, name, env))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		return err
	})
}
