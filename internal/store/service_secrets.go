package store

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hanzoai/base/core"
)

const serviceSecretsCollection = "kms_service_secrets"

var (
	ErrServiceSecretNotFound = errors.New("store: service secret not found")
	ErrServiceSecretExists   = errors.New("store: service secret already exists")
)

// ServiceSecret is a server-side encrypted secret for service-to-service use.
// Unlike ZK secrets (client-side encrypted), these are encrypted at rest by Base
// and decrypted by the KMS server on read. Services authenticate via IAM JWT.
type ServiceSecret struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`
	Path  string `json:"path"`  // e.g. "providers/alpaca/dev"
	Name  string `json:"name"`  // e.g. "api_key"
	Value string `json:"value"` // plaintext (encrypted at rest by Base CEK)
}

// ServiceSecretStore provides CRUD for server-side encrypted service secrets.
type ServiceSecretStore struct {
	app core.App
}

// NewServiceSecretStore creates a service secret store backed by Base.
func NewServiceSecretStore(app core.App) *ServiceSecretStore {
	return &ServiceSecretStore{app: app}
}

// Put creates or updates a service secret.
func (s *ServiceSecretStore) Put(sec *ServiceSecret) error {
	col, err := s.app.FindCollectionByNameOrId(serviceSecretsCollection)
	if err != nil {
		return fmt.Errorf("store: collection %s: %w", serviceSecretsCollection, err)
	}

	// Check for existing — upsert semantics.
	existing, _ := s.app.FindFirstRecordByFilter(
		serviceSecretsCollection,
		"org_id = {:org} && path = {:path} && name = {:name}",
		map[string]any{"org": sec.OrgID, "path": sec.Path, "name": sec.Name},
	)
	if existing != nil {
		existing.Set("value", sec.Value)
		if err := s.app.Save(existing); err != nil {
			return fmt.Errorf("store: update service secret: %w", err)
		}
		sec.ID = existing.Id
		return nil
	}

	rec := core.NewRecord(col)
	rec.Set("org_id", sec.OrgID)
	rec.Set("path", sec.Path)
	rec.Set("name", sec.Name)
	rec.Set("value", sec.Value)
	if err := s.app.Save(rec); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrServiceSecretExists
		}
		return fmt.Errorf("store: save service secret: %w", err)
	}
	sec.ID = rec.Id
	return nil
}

// Get retrieves a service secret by org, path, and name.
func (s *ServiceSecretStore) Get(orgID, path, name string) (*ServiceSecret, error) {
	rec, err := s.app.FindFirstRecordByFilter(
		serviceSecretsCollection,
		"org_id = {:org} && path = {:path} && name = {:name}",
		map[string]any{"org": orgID, "path": path, "name": name},
	)
	if err != nil {
		return nil, ErrServiceSecretNotFound
	}
	return recordToServiceSecret(rec), nil
}

// Delete removes a service secret.
func (s *ServiceSecretStore) Delete(orgID, path, name string) error {
	rec, err := s.app.FindFirstRecordByFilter(
		serviceSecretsCollection,
		"org_id = {:org} && path = {:path} && name = {:name}",
		map[string]any{"org": orgID, "path": path, "name": name},
	)
	if err != nil {
		return ErrServiceSecretNotFound
	}
	return s.app.Delete(rec)
}

// List returns all service secret names (not values) for an org, optionally filtered by path prefix.
func (s *ServiceSecretStore) List(orgID, pathPrefix string) ([]*ServiceSecret, error) {
	filter := "org_id = {:org}"
	params := map[string]any{"org": orgID}
	if pathPrefix != "" {
		filter += " && path ~ {:prefix}"
		params["prefix"] = pathPrefix + "%"
	}

	records, err := s.app.FindRecordsByFilter(
		serviceSecretsCollection,
		filter,
		"", 0, 0,
		params,
	)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: list service secrets: %w", err)
	}
	out := make([]*ServiceSecret, 0, len(records))
	for _, r := range records {
		ss := recordToServiceSecret(r)
		ss.Value = "" // never return values in list
		out = append(out, ss)
	}
	return out, nil
}

func recordToServiceSecret(r *core.Record) *ServiceSecret {
	return &ServiceSecret{
		ID:    r.Id,
		OrgID: r.GetString("org_id"),
		Path:  r.GetString("path"),
		Name:  r.GetString("name"),
		Value: r.GetString("value"),
	}
}
