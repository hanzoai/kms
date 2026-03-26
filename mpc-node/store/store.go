// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

// Package store provides an encrypted key-value store backed by ZapDB.
// Each MPC node has its own isolated ZapDB instance with encryption at rest.
package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	badger "github.com/luxfi/zapdb/v4"
)

var (
	ErrNotFound = errors.New("store: key not found")
	ErrClosed   = errors.New("store: closed")
)

// Store wraps a ZapDB instance with encryption at rest and org-scoped key prefixes.
type Store struct {
	db     *badger.DB
	mu     sync.RWMutex
	closed bool
}

// NewStore opens (or creates) a ZapDB database at path, encrypted with encryptionKey.
// The encryptionKey must be exactly 16, 24, or 32 bytes (AES key sizes).
func NewStore(path string, encryptionKey []byte) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: path required")
	}
	if len(encryptionKey) != 16 && len(encryptionKey) != 24 && len(encryptionKey) != 32 {
		return nil, fmt.Errorf("store: encryption key must be 16, 24, or 32 bytes, got %d", len(encryptionKey))
	}

	opts := badger.DefaultOptions(path)
	opts.EncryptionKey = encryptionKey
	opts.IndexCacheSize = 64 << 20   // 64 MB
	opts.BlockCacheSize = 128 << 20  // 128 MB — required when encryption is enabled
	opts.Logger = nil                // silent
	opts.SyncWrites = true           // durability for secrets
	opts.NumCompactors = 2
	opts.DetectConflicts = false

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("store: open zapdb: %w", err)
	}
	return &Store{db: db}, nil
}

// PutSecret stores an encrypted secret blob under org/<slug>/secret/<key>.
func (s *Store) PutSecret(orgSlug, key string, encryptedBlob []byte) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	return s.put(SecretKey(orgSlug, key), encryptedBlob)
}

// GetSecret retrieves an encrypted secret blob.
func (s *Store) GetSecret(orgSlug, key string) ([]byte, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	return s.get(SecretKey(orgSlug, key))
}

// ListSecrets returns all secret key names for an org.
func (s *Store) ListSecrets(orgSlug string) ([]string, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	prefix := SecretPrefix(orgSlug)
	var keys []string
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			if !bytes.HasPrefix(k, prefix) {
				break
			}
			// Strip the prefix to get the secret name.
			name := string(k[len(prefix):])
			keys = append(keys, name)
		}
		return nil
	})
	return keys, err
}

// PutShard stores this node's Shamir shard for an org.
func (s *Store) PutShard(orgSlug string, shard []byte) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	return s.put(ShardKey(orgSlug), shard)
}

// GetShard retrieves this node's Shamir shard for an org.
func (s *Store) GetShard(orgSlug string) ([]byte, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	return s.get(ShardKey(orgSlug))
}

// PutCRDTOp appends an FHE-encrypted CRDT operation to the log.
// The sequence number is auto-assigned.
func (s *Store) PutCRDTOp(orgSlug string, op []byte) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	// Determine the next sequence number by counting existing ops.
	seq, err := s.nextCRDTSeq(orgSlug)
	if err != nil {
		return fmt.Errorf("store: crdt seq: %w", err)
	}
	return s.put(CRDTKey(orgSlug, seq), op)
}

// GetCRDTOps returns all CRDT ops for an org with sequence >= since.
func (s *Store) GetCRDTOps(orgSlug string, since uint64) ([][]byte, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	prefix := CRDTPrefix(orgSlug)
	startKey := CRDTKey(orgSlug, since)
	var ops [][]byte
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(startKey); it.Valid(); it.Next() {
			item := it.Item()
			if !bytes.HasPrefix(item.Key(), prefix) {
				break
			}
			val, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			ops = append(ops, val)
		}
		return nil
	})
	return ops, err
}

// PutAuditEntry appends an audit log entry. Sequence is auto-assigned.
func (s *Store) PutAuditEntry(orgSlug string, entry []byte) (uint64, error) {
	if err := s.ensureOpen(); err != nil {
		return 0, err
	}
	seq, err := s.nextAuditSeq(orgSlug)
	if err != nil {
		return 0, fmt.Errorf("store: audit seq: %w", err)
	}
	return seq, s.put(AuditKey(orgSlug, seq), entry)
}

// GetAuditEntries returns audit entries for an org within the given sequence range.
func (s *Store) GetAuditEntries(orgSlug string, since uint64) ([][]byte, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	prefix := AuditPrefix(orgSlug)
	startKey := AuditKey(orgSlug, since)
	var entries [][]byte
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(startKey); it.Valid(); it.Next() {
			item := it.Item()
			if !bytes.HasPrefix(item.Key(), prefix) {
				break
			}
			val, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			entries = append(entries, val)
		}
		return nil
	})
	return entries, err
}

// PutEscrowShard stores an escrow shard for an org.
func (s *Store) PutEscrowShard(orgSlug string, wrappedShard []byte) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	return s.put(EscrowKey(orgSlug), wrappedShard)
}

// GetEscrowShard retrieves the escrow shard for an org.
func (s *Store) GetEscrowShard(orgSlug string) ([]byte, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	return s.get(EscrowKey(orgSlug))
}

// PutRetention stores a retention record for a secret.
func (s *Store) PutRetention(orgSlug, secretKey string, record []byte) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	return s.put(RetentionKey(orgSlug, secretKey), record)
}

// GetRetention retrieves a retention record for a secret.
func (s *Store) GetRetention(orgSlug, secretKey string) ([]byte, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	return s.get(RetentionKey(orgSlug, secretKey))
}

// DeleteRetention removes a retention record (only after policy expires).
func (s *Store) DeleteRetention(orgSlug, secretKey string) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	key := RetentionKey(orgSlug, secretKey)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

// ListRetentionKeys returns all retention record keys for an org.
func (s *Store) ListRetentionKeys(orgSlug string) ([]string, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	prefix := RetentionPrefix(orgSlug)
	var keys []string
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			if !bytes.HasPrefix(k, prefix) {
				break
			}
			name := string(k[len(prefix):])
			keys = append(keys, name)
		}
		return nil
	})
	return keys, err
}

// PutBreakGlass stores a break-glass token record.
func (s *Store) PutBreakGlass(token string, record []byte) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	return s.put(BreakGlassKey(token), record)
}

// GetBreakGlass retrieves a break-glass token record.
func (s *Store) GetBreakGlass(token string) ([]byte, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	return s.get(BreakGlassKey(token))
}

// DeleteBreakGlass removes a break-glass token (revocation).
func (s *Store) DeleteBreakGlass(token string) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	key := BreakGlassKey(token)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

// DeleteSecret removes a secret. Used by retention enforcement.
func (s *Store) DeleteSecret(orgSlug, key string) error {
	if err := s.ensureOpen(); err != nil {
		return err
	}
	dbKey := SecretKey(orgSlug, key)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(dbKey)
	})
}

// Close closes the underlying ZapDB.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

// --- internal helpers ---

func (s *Store) ensureOpen() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	return nil
}

func (s *Store) put(key, value []byte) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

func (s *Store) get(key []byte) ([]byte, error) {
	var val []byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return ErrNotFound
			}
			return err
		}
		val, err = item.ValueCopy(nil)
		return err
	})
	return val, err
}

func (s *Store) nextAuditSeq(orgSlug string) (uint64, error) {
	counterKey := []byte(fmt.Sprintf("org/%s/audit_seq", orgSlug))
	var seq uint64
	err := s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(counterKey)
		if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		if err == nil {
			val, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			seq = binary.BigEndian.Uint64(val)
		}
		next := seq + 1
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, next)
		if err := txn.Set(counterKey, buf); err != nil {
			return err
		}
		return nil
	})
	return seq, err
}

func (s *Store) nextCRDTSeq(orgSlug string) (uint64, error) {
	// Use a counter key to track the next sequence atomically.
	counterKey := []byte(fmt.Sprintf("org/%s/crdt_seq", orgSlug))
	var seq uint64
	err := s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(counterKey)
		if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		if err == nil {
			val, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			seq = binary.BigEndian.Uint64(val)
		}
		// Increment and store.
		next := seq + 1
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, next)
		if err := txn.Set(counterKey, buf); err != nil {
			return err
		}
		return nil
	})
	return seq, err
}
