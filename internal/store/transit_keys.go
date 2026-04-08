package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hanzoai/base/core"
)

var (
	ErrTransitKeyNotFound = errors.New("store: transit key not found")
	ErrTransitKeyExists   = errors.New("store: transit key already exists")
)

const transitKeysCollection = "kms_transit_keys"

// TransitKeyRecord holds a transit key ring in the store.
type TransitKeyRecord struct {
	Name          string `json:"name"`
	KeyType       string `json:"key_type"`
	LatestVersion int    `json:"latest_version"`
	KeyRing       string `json:"key_ring"` // JSON-encoded key ring
	Exportable    bool   `json:"exportable"`
}

// TransitKeyStore provides CRUD for transit encryption keys.
type TransitKeyStore struct {
	app core.App
}

// NewTransitKeyStore creates a transit key store backed by Base.
func NewTransitKeyStore(app core.App) *TransitKeyStore {
	return &TransitKeyStore{app: app}
}

// Create stores a new transit key.
func (s *TransitKeyStore) Create(k *TransitKeyRecord) error {
	col, err := s.app.FindCollectionByNameOrId(transitKeysCollection)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}

	_, findErr := s.app.FindFirstRecordByFilter(transitKeysCollection, "name = {:n}", map[string]any{"n": k.Name})
	if findErr == nil {
		return ErrTransitKeyExists
	}

	rec := core.NewRecord(col)
	rec.Set("name", k.Name)
	rec.Set("key_type", k.KeyType)
	rec.Set("latest_version", k.LatestVersion)
	rec.Set("key_ring", k.KeyRing)
	rec.Set("exportable", k.Exportable)
	return s.app.Save(rec)
}

// Get retrieves a transit key by name.
func (s *TransitKeyStore) Get(name string) (*TransitKeyRecord, error) {
	rec, err := s.app.FindFirstRecordByFilter(transitKeysCollection, "name = {:n}", map[string]any{"n": name})
	if err != nil {
		return nil, ErrTransitKeyNotFound
	}
	return recordToTransitKey(rec), nil
}

// Update replaces a transit key record.
func (s *TransitKeyStore) Update(k *TransitKeyRecord) error {
	rec, err := s.app.FindFirstRecordByFilter(transitKeysCollection, "name = {:n}", map[string]any{"n": k.Name})
	if err != nil {
		return ErrTransitKeyNotFound
	}
	rec.Set("key_type", k.KeyType)
	rec.Set("latest_version", k.LatestVersion)
	rec.Set("key_ring", k.KeyRing)
	rec.Set("exportable", k.Exportable)
	return s.app.Save(rec)
}

// List returns all transit keys.
func (s *TransitKeyStore) List() ([]*TransitKeyRecord, error) {
	records, err := s.app.FindAllRecords(transitKeysCollection)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: list transit keys: %w", err)
	}
	out := make([]*TransitKeyRecord, 0, len(records))
	for _, r := range records {
		out = append(out, recordToTransitKey(r))
	}
	return out, nil
}

// Delete removes a transit key by name.
func (s *TransitKeyStore) Delete(name string) error {
	rec, err := s.app.FindFirstRecordByFilter(transitKeysCollection, "name = {:n}", map[string]any{"n": name})
	if err != nil {
		return ErrTransitKeyNotFound
	}
	return s.app.Delete(rec)
}

func recordToTransitKey(r *core.Record) *TransitKeyRecord {
	exportable := r.GetBool("exportable")
	return &TransitKeyRecord{
		Name:          r.GetString("name"),
		KeyType:       r.GetString("key_type"),
		LatestVersion: int(r.GetFloat("latest_version")),
		KeyRing:       r.GetString("key_ring"),
		Exportable:    exportable,
	}
}

// MarshalKeyRing encodes a key ring map to JSON for storage.
func MarshalKeyRing(ring map[int][]byte) (string, error) {
	// Convert int keys to strings for JSON.
	m := make(map[string][]byte, len(ring))
	for v, k := range ring {
		m[fmt.Sprintf("%d", v)] = k
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// UnmarshalKeyRing decodes a JSON key ring from storage.
func UnmarshalKeyRing(s string) (map[int][]byte, error) {
	var m map[string][]byte
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	ring := make(map[int][]byte, len(m))
	for k, v := range m {
		var ver int
		if _, err := fmt.Sscanf(k, "%d", &ver); err != nil {
			return nil, fmt.Errorf("store: invalid key ring version %q: %w", k, err)
		}
		ring[ver] = v
	}
	return ring, nil
}
