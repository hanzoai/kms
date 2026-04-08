package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hanzoai/base/core"
)

var (
	ErrKeyNotFound = errors.New("store: key set not found")
	ErrKeyExists   = errors.New("store: key set already exists")
)

const keysCollection = "kms_validator_keys"

// ValidatorKeySet holds MPC wallet references for a validator.
type ValidatorKeySet struct {
	ValidatorID       string `json:"validator_id"`
	BLSWalletID       string `json:"bls_wallet_id"`
	RingtailWalletID  string `json:"ringtail_wallet_id"`
	BLSPublicKey      string `json:"bls_public_key"`
	RingtailPublicKey string `json:"ringtail_public_key"`
	Threshold         int    `json:"threshold"`
	Parties           int    `json:"parties"`
	Status            string `json:"status"`
}

// KeyStore provides CRUD for validator key sets.
type KeyStore struct {
	app core.App
}

// NewKeyStore creates a key store backed by Base.
func NewKeyStore(app core.App) *KeyStore {
	return &KeyStore{app: app}
}

// Put stores a new validator key set.
func (s *KeyStore) Put(ks *ValidatorKeySet) error {
	col, err := s.app.FindCollectionByNameOrId(keysCollection)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}

	// Check for existing.
	_, findErr := s.app.FindFirstRecordByFilter(keysCollection, "validator_id = {:vid}", map[string]any{"vid": ks.ValidatorID})
	if findErr == nil {
		return ErrKeyExists
	}

	data, err := json.Marshal(ks)
	if err != nil {
		return err
	}

	rec := core.NewRecord(col)
	rec.Set("validator_id", ks.ValidatorID)
	rec.Set("data", string(data))
	return s.app.Save(rec)
}

// Get retrieves a key set by validator ID.
func (s *KeyStore) Get(validatorID string) (*ValidatorKeySet, error) {
	rec, err := s.app.FindFirstRecordByFilter(keysCollection, "validator_id = {:vid}", map[string]any{"vid": validatorID})
	if err != nil {
		return nil, ErrKeyNotFound
	}
	var ks ValidatorKeySet
	if err := json.Unmarshal([]byte(rec.GetString("data")), &ks); err != nil {
		return nil, fmt.Errorf("store: decode key set: %w", err)
	}
	return &ks, nil
}

// List returns all key sets.
func (s *KeyStore) List() ([]*ValidatorKeySet, error) {
	records, err := s.app.FindAllRecords(keysCollection)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: list keys: %w", err)
	}
	out := make([]*ValidatorKeySet, 0, len(records))
	for _, r := range records {
		var ks ValidatorKeySet
		if err := json.Unmarshal([]byte(r.GetString("data")), &ks); err != nil {
			continue
		}
		out = append(out, &ks)
	}
	return out, nil
}

// Update replaces an existing key set.
func (s *KeyStore) Update(ks *ValidatorKeySet) error {
	rec, err := s.app.FindFirstRecordByFilter(keysCollection, "validator_id = {:vid}", map[string]any{"vid": ks.ValidatorID})
	if err != nil {
		return ErrKeyNotFound
	}
	data, err := json.Marshal(ks)
	if err != nil {
		return err
	}
	rec.Set("data", string(data))
	return s.app.Save(rec)
}

// Delete removes a key set by validator ID.
func (s *KeyStore) Delete(validatorID string) error {
	rec, err := s.app.FindFirstRecordByFilter(keysCollection, "validator_id = {:vid}", map[string]any{"vid": validatorID})
	if err != nil {
		return ErrKeyNotFound
	}
	return s.app.Delete(rec)
}
