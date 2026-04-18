package store

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/base/core"
)

const secretVersionsCollection = "kms_secret_versions"

// ErrSecretVersionNotFound is returned when a version row is missing.
var ErrSecretVersionNotFound = errors.New("store: secret version not found")

// SecretVersion is one immutable version of a secret value. Old versions are
// retained for rollback/audit until explicit destroy.
type SecretVersion struct {
	SecretID    string `json:"secretId"`
	Version     int    `json:"version"`
	Status      string `json:"status"` // active | deprecated | destroyed
	Value       string `json:"value,omitempty"`
	CreatedAt   string `json:"createdAt"`
	DestroyedAt string `json:"destroyedAt,omitempty"`
}

// SecretVersionStore manages the immutable version history for secret values.
type SecretVersionStore struct {
	app core.App
}

// NewSecretVersionStore constructs a store.
func NewSecretVersionStore(app core.App) *SecretVersionStore {
	return &SecretVersionStore{app: app}
}

// Append creates a new version row and marks all previous active versions as
// deprecated. Returns the new version number (1-indexed).
func (s *SecretVersionStore) Append(secretID, value string) (int, error) {
	col, err := s.app.FindCollectionByNameOrId(secretVersionsCollection)
	if err != nil {
		return 0, fmt.Errorf("store: collection %s: %w", secretVersionsCollection, err)
	}

	// Find the current max version.
	records, _ := s.app.FindRecordsByFilter(
		secretVersionsCollection,
		"secret_id = {:sid}",
		"-version", 0, 0,
		map[string]any{"sid": secretID},
	)
	version := 1
	for _, r := range records {
		if r.GetString("status") == "active" {
			r.Set("status", "deprecated")
			if err := s.app.Save(r); err != nil {
				return 0, fmt.Errorf("store: deprecate previous version: %w", err)
			}
		}
		if v := int(r.GetFloat("version")); v >= version {
			version = v + 1
		}
	}

	rec := core.NewRecord(col)
	rec.Set("secret_id", secretID)
	rec.Set("version", version)
	rec.Set("status", "active")
	rec.Set("value", value)
	if err := s.app.Save(rec); err != nil {
		return 0, fmt.Errorf("store: save secret version: %w", err)
	}
	return version, nil
}

// List returns all versions for a secret, newest first.
func (s *SecretVersionStore) List(secretID string) ([]*SecretVersion, error) {
	records, err := s.app.FindRecordsByFilter(
		secretVersionsCollection,
		"secret_id = {:sid}",
		"-version", 0, 0,
		map[string]any{"sid": secretID},
	)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: list versions: %w", err)
	}
	out := make([]*SecretVersion, 0, len(records))
	for _, r := range records {
		out = append(out, recordToSecretVersion(r))
	}
	return out, nil
}

// Current returns the single active version for a secret.
func (s *SecretVersionStore) Current(secretID string) (*SecretVersion, error) {
	rec, err := s.app.FindFirstRecordByFilter(
		secretVersionsCollection,
		"secret_id = {:sid} && status = 'active'",
		map[string]any{"sid": secretID},
	)
	if err != nil {
		return nil, ErrSecretVersionNotFound
	}
	return recordToSecretVersion(rec), nil
}

// Destroy marks a specific version destroyed and clears the value.
func (s *SecretVersionStore) Destroy(secretID string, version int) error {
	rec, err := s.app.FindFirstRecordByFilter(
		secretVersionsCollection,
		"secret_id = {:sid} && version = {:v}",
		map[string]any{"sid": secretID, "v": version},
	)
	if err != nil {
		return ErrSecretVersionNotFound
	}
	rec.Set("status", "destroyed")
	rec.Set("value", "")
	rec.Set("destroyed_at", time.Now().UTC().Format(time.RFC3339))
	return s.app.Save(rec)
}

func recordToSecretVersion(r *core.Record) *SecretVersion {
	return &SecretVersion{
		SecretID:    r.GetString("secret_id"),
		Version:     int(r.GetFloat("version")),
		Status:      r.GetString("status"),
		Value:       r.GetString("value"),
		CreatedAt:   r.GetString("created"),
		DestroyedAt: r.GetString("destroyed_at"),
	}
}
