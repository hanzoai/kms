package transit

import (
	"testing"

	"github.com/hanzoai/kms/internal/store"
)

// memKeyStore is an in-memory KeyStore for testing.
type memKeyStore struct {
	data map[string]*store.TransitKeyRecord
}

func newMemKeyStore() *memKeyStore {
	return &memKeyStore{data: make(map[string]*store.TransitKeyRecord)}
}

func (s *memKeyStore) Create(k *store.TransitKeyRecord) error {
	if _, ok := s.data[k.Name]; ok {
		return store.ErrTransitKeyExists
	}
	cp := *k
	s.data[k.Name] = &cp
	return nil
}

func (s *memKeyStore) Get(name string) (*store.TransitKeyRecord, error) {
	k, ok := s.data[name]
	if !ok {
		return nil, store.ErrTransitKeyNotFound
	}
	cp := *k
	return &cp, nil
}

func (s *memKeyStore) Update(k *store.TransitKeyRecord) error {
	if _, ok := s.data[k.Name]; !ok {
		return store.ErrTransitKeyNotFound
	}
	cp := *k
	s.data[k.Name] = &cp
	return nil
}

func (s *memKeyStore) List() ([]*store.TransitKeyRecord, error) {
	out := make([]*store.TransitKeyRecord, 0, len(s.data))
	for _, k := range s.data {
		cp := *k
		out = append(out, &cp)
	}
	return out, nil
}

func (s *memKeyStore) Delete(name string) error {
	if _, ok := s.data[name]; !ok {
		return store.ErrTransitKeyNotFound
	}
	delete(s.data, name)
	return nil
}

func newTestEngine(t *testing.T) (*Engine, func()) {
	t.Helper()
	return NewEngine(newMemKeyStore()), func() {}
}
