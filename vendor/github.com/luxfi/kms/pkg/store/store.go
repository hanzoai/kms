// Package store provides key metadata and secret persistence via ZapDB.
// ZapDB is an embedded LSM key-value store with built-in S3 replication.
// No SQLite, no PostgreSQL, no Base dependency.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	badger "github.com/luxfi/zapdb"
	"github.com/luxfi/kms/pkg/keys"
)

var (
	ErrNotFound      = errors.New("store: key set not found")
	ErrAlreadyExists = errors.New("store: key set already exists")
)

// Key prefix for validator key sets in ZapDB.
var keyPrefix = []byte("kms/keys/")

// Store persists validator key set metadata in ZapDB.
type Store struct {
	db   *badger.DB
	mu   sync.RWMutex
	data map[string]*keys.ValidatorKeySet
}

// New creates a Store backed by a ZapDB instance.
func New(db *badger.DB) (*Store, error) {
	s := &Store{
		db:   db,
		data: make(map[string]*keys.ValidatorKeySet),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load reads all validator key sets from ZapDB into memory.
func (s *Store) load() error {
	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = keyPrefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var ks keys.ValidatorKeySet
				if err := json.Unmarshal(val, &ks); err != nil {
					return fmt.Errorf("store: corrupt record key=%s: %w", item.Key(), err)
				}
				s.data[ks.ValidatorID] = &ks
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// dbKey returns the ZapDB key for a validator ID.
func dbKey(validatorID string) []byte {
	return append(keyPrefix, []byte(validatorID)...)
}

// Put saves a validator key set. Returns ErrAlreadyExists if the validator ID is taken.
func (s *Store) Put(ks *keys.ValidatorKeySet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[ks.ValidatorID]; exists {
		return ErrAlreadyExists
	}
	s.data[ks.ValidatorID] = ks
	return s.persist(ks)
}

// Update replaces an existing validator key set.
func (s *Store) Update(ks *keys.ValidatorKeySet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[ks.ValidatorID]; !exists {
		return ErrNotFound
	}
	s.data[ks.ValidatorID] = ks
	return s.persist(ks)
}

// Get retrieves a validator key set by validator ID.
func (s *Store) Get(validatorID string) (*keys.ValidatorKeySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ks, ok := s.data[validatorID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *ks
	return &cp, nil
}

// List returns all validator key sets.
func (s *Store) List() []*keys.ValidatorKeySet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*keys.ValidatorKeySet, 0, len(s.data))
	for _, ks := range s.data {
		cp := *ks
		result = append(result, &cp)
	}
	return result
}

// Delete removes a validator key set by validator ID.
func (s *Store) Delete(validatorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[validatorID]; !exists {
		return ErrNotFound
	}
	delete(s.data, validatorID)

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(dbKey(validatorID))
	})
}

// persist writes a key set to ZapDB.
func (s *Store) persist(ks *keys.ValidatorKeySet) error {
	raw, err := json.Marshal(ks)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(dbKey(ks.ValidatorID), raw)
	})
}
