package store

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hanzoai/base/core"
)

var (
	ErrSecretNotFound = errors.New("store: secret not found")
	ErrSecretExists   = errors.New("store: secret already exists")
)

const secretsCollection = "kms_secrets"

// Secret is the stored encrypted secret record.
type Secret struct {
	ID         string `json:"id"`
	OrgID      string `json:"org_id"`
	Path       string `json:"path"`
	Name       string `json:"name"`
	Env        string `json:"env,omitempty"`
	Ciphertext string `json:"ciphertext"`
	WrappedDEK string `json:"wrapped_dek"`
}

// SecretStore provides CRUD for encrypted secrets.
type SecretStore struct {
	app core.App
}

// NewSecretStore creates a secret store backed by Base.
func NewSecretStore(app core.App) *SecretStore {
	return &SecretStore{app: app}
}

// Create stores a new encrypted secret.
func (s *SecretStore) Create(sec *Secret) error {
	col, err := s.app.FindCollectionByNameOrId(secretsCollection)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	rec := core.NewRecord(col)
	rec.Set("org_id", sec.OrgID)
	rec.Set("path", sec.Path)
	rec.Set("name", sec.Name)
	rec.Set("env", sec.Env)
	rec.Set("ciphertext", sec.Ciphertext)
	rec.Set("wrapped_dek", sec.WrappedDEK)
	if err := s.app.Save(rec); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrSecretExists
		}
		return fmt.Errorf("store: save secret: %w", err)
	}
	sec.ID = rec.Id
	return nil
}

// Get retrieves an encrypted secret by org, path, and name.
func (s *SecretStore) Get(orgID, path, name string) (*Secret, error) {
	rec, err := s.app.FindFirstRecordByFilter(
		secretsCollection,
		"org_id = {:org} && path = {:path} && name = {:name}",
		map[string]any{"org": orgID, "path": path, "name": name},
	)
	if err != nil {
		return nil, ErrSecretNotFound
	}
	return recordToSecret(rec), nil
}

// List returns all encrypted secrets for an org.
func (s *SecretStore) List(orgID string) ([]*Secret, error) {
	records, err := s.app.FindRecordsByFilter(
		secretsCollection,
		"org_id = {:org}",
		"", 0, 0,
		map[string]any{"org": orgID},
	)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: list secrets: %w", err)
	}
	out := make([]*Secret, 0, len(records))
	for _, r := range records {
		out = append(out, recordToSecret(r))
	}
	return out, nil
}

// Delete removes an encrypted secret.
func (s *SecretStore) Delete(orgID, path, name string) error {
	rec, err := s.app.FindFirstRecordByFilter(
		secretsCollection,
		"org_id = {:org} && path = {:path} && name = {:name}",
		map[string]any{"org": orgID, "path": path, "name": name},
	)
	if err != nil {
		return ErrSecretNotFound
	}
	return s.app.Delete(rec)
}

func recordToSecret(r *core.Record) *Secret {
	return &Secret{
		ID:         r.Id,
		OrgID:      r.GetString("org_id"),
		Path:       r.GetString("path"),
		Name:       r.GetString("name"),
		Env:        r.GetString("env"),
		Ciphertext: r.GetString("ciphertext"),
		WrappedDEK: r.GetString("wrapped_dek"),
	}
}
