package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/base/core"
)

const serviceSecretsCollection = "kms_service_secrets"

var (
	// ErrServiceSecretNotFound is returned when a secret is not found.
	ErrServiceSecretNotFound = errors.New("store: service secret not found")
	// ErrServiceSecretExists is returned when a create collides with the
	// (org, path, name) uniqueness constraint.
	ErrServiceSecretExists = errors.New("store: service secret already exists")
)

// ServiceSecret is a server-side encrypted secret for service-to-service use.
// Unlike ZK secrets (client-side encrypted), these are encrypted at rest by
// Base and decrypted by the KMS server on read. Services authenticate via
// IAM JWT. (tenant_id == org_id == IAM owner slug.)
type ServiceSecret struct {
	// SecretID is the Base record id — the canonical stable alias. Always
	// populated on responses.
	SecretID string `json:"secretId"`
	// ID is kept as a legacy field name; equal to SecretID.
	ID         string            `json:"id"`
	OrgID      string            `json:"org_id"`
	TenantID   string            `json:"tenantId"`
	Path       string            `json:"path"`
	Name       string            `json:"name"`
	Value      string            `json:"value,omitempty"`
	SecretType string            `json:"secretType,omitempty"`
	Status     string            `json:"status,omitempty"`
	Version    int               `json:"version,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	CreatedAt  string            `json:"createdAt,omitempty"`
	UpdatedAt  string            `json:"updatedAt,omitempty"`
	RotatedAt  string            `json:"rotatedAt,omitempty"`
}

// ServiceSecretStore provides CRUD for server-side encrypted service secrets.
type ServiceSecretStore struct {
	app      core.App
	versions *SecretVersionStore
}

// NewServiceSecretStore creates a service secret store backed by Base.
func NewServiceSecretStore(app core.App) *ServiceSecretStore {
	return &ServiceSecretStore{app: app, versions: NewSecretVersionStore(app)}
}

// Put creates or updates a service secret. Every update creates a new version
// row. Returns the stored secret (including secret_id) with version set.
func (s *ServiceSecretStore) Put(sec *ServiceSecret) error {
	col, err := s.app.FindCollectionByNameOrId(serviceSecretsCollection)
	if err != nil {
		return fmt.Errorf("store: collection %s: %w", serviceSecretsCollection, err)
	}

	metaJSON, _ := json.Marshal(sec.Metadata)

	existing, _ := s.app.FindFirstRecordByFilter(
		serviceSecretsCollection,
		"org_id = {:org} && path = {:path} && name = {:name}",
		map[string]any{"org": sec.OrgID, "path": sec.Path, "name": sec.Name},
	)
	if existing != nil {
		existing.Set("value", sec.Value)
		if sec.SecretType != "" {
			existing.Set("secret_type", sec.SecretType)
		}
		if sec.Metadata != nil {
			existing.Set("metadata", string(metaJSON))
		}
		existing.Set("status", "active")
		if err := s.app.Save(existing); err != nil {
			return fmt.Errorf("store: update service secret: %w", err)
		}
		sec.SecretID = existing.Id
		sec.ID = existing.Id
		sec.TenantID = existing.GetString("org_id")
		v, err := s.versions.Append(existing.Id, sec.Value)
		if err != nil {
			return fmt.Errorf("store: version append: %w", err)
		}
		sec.Version = v
		sec.UpdatedAt = existing.GetString("updated")
		return nil
	}

	rec := core.NewRecord(col)
	rec.Set("org_id", sec.OrgID)
	rec.Set("path", sec.Path)
	rec.Set("name", sec.Name)
	rec.Set("value", sec.Value)
	if sec.SecretType != "" {
		rec.Set("secret_type", sec.SecretType)
	}
	if sec.Metadata != nil {
		rec.Set("metadata", string(metaJSON))
	}
	rec.Set("status", "active")
	if err := s.app.Save(rec); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrServiceSecretExists
		}
		return fmt.Errorf("store: save service secret: %w", err)
	}
	sec.SecretID = rec.Id
	sec.ID = rec.Id
	sec.TenantID = rec.GetString("org_id")
	v, err := s.versions.Append(rec.Id, sec.Value)
	if err != nil {
		return fmt.Errorf("store: version append: %w", err)
	}
	sec.Version = v
	sec.CreatedAt = rec.GetString("created")
	sec.UpdatedAt = rec.GetString("updated")
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

// GetByID retrieves a service secret by its secret_id (Base record id).
func (s *ServiceSecretStore) GetByID(secretID string) (*ServiceSecret, error) {
	rec, err := s.app.FindRecordById(serviceSecretsCollection, secretID)
	if err != nil {
		return nil, ErrServiceSecretNotFound
	}
	return recordToServiceSecret(rec), nil
}

// Delete removes a service secret and all its versions.
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

// DeleteByID removes by id. Returns ErrServiceSecretNotFound if missing.
func (s *ServiceSecretStore) DeleteByID(secretID string) error {
	rec, err := s.app.FindRecordById(serviceSecretsCollection, secretID)
	if err != nil {
		return ErrServiceSecretNotFound
	}
	return s.app.Delete(rec)
}

// Update patches a secret by id. If newValue != "", creates a new version
// and marks the previous version deprecated; merges metadata keys.
func (s *ServiceSecretStore) Update(secretID, newValue string, metadata map[string]string) (*ServiceSecret, error) {
	rec, err := s.app.FindRecordById(serviceSecretsCollection, secretID)
	if err != nil {
		return nil, ErrServiceSecretNotFound
	}
	if newValue != "" {
		rec.Set("value", newValue)
	}
	if metadata != nil {
		existing := map[string]string{}
		if raw := rec.GetString("metadata"); raw != "" {
			_ = json.Unmarshal([]byte(raw), &existing)
		}
		for k, v := range metadata {
			existing[k] = v
		}
		j, _ := json.Marshal(existing)
		rec.Set("metadata", string(j))
	}
	rec.Set("status", "active")
	if err := s.app.Save(rec); err != nil {
		return nil, fmt.Errorf("store: update service secret: %w", err)
	}
	out := recordToServiceSecret(rec)
	if newValue != "" {
		v, err := s.versions.Append(rec.Id, newValue)
		if err != nil {
			return nil, fmt.Errorf("store: version append: %w", err)
		}
		out.Version = v
	}
	return out, nil
}

// Rotate creates a new version without destroying older ones. Returns the
// updated secret and the new version number.
func (s *ServiceSecretStore) Rotate(secretID, newValue string) (*ServiceSecret, int, error) {
	rec, err := s.app.FindRecordById(serviceSecretsCollection, secretID)
	if err != nil {
		return nil, 0, ErrServiceSecretNotFound
	}
	rec.Set("value", newValue)
	rec.Set("status", "active")
	rec.Set("rotated_at", time.Now().UTC().Format(time.RFC3339))
	if err := s.app.Save(rec); err != nil {
		return nil, 0, fmt.Errorf("store: rotate service secret: %w", err)
	}
	v, err := s.versions.Append(rec.Id, newValue)
	if err != nil {
		return nil, 0, fmt.Errorf("store: version append: %w", err)
	}
	out := recordToServiceSecret(rec)
	out.Version = v
	return out, v, nil
}

// List returns all service secret names (not values) for an org, optionally
// filtered by path prefix.
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

// ListAll returns secret metadata across all tenants, optionally filtered by
// tenantId and/or secretType. Intended for admin listings — callers must
// gate this on `kms.admin`.
//
// F13: When both filter arguments are empty, pass a tautology filter
// ("id != ''") instead of an empty string — Base's FindRecordsByFilter
// treats "" as "return nothing" on some backends, which would silently
// omit all secrets.
func (s *ServiceSecretStore) ListAll(tenantID, secretType string) ([]*ServiceSecret, error) {
	var clauses []string
	params := map[string]any{}
	if tenantID != "" {
		clauses = append(clauses, "org_id = {:tid}")
		params["tid"] = tenantID
	}
	if secretType != "" {
		clauses = append(clauses, "secret_type = {:st}")
		params["st"] = secretType
	}
	filter := strings.Join(clauses, " && ")
	if filter == "" {
		filter = "id != ''" // match-all sentinel
	}

	records, err := s.app.FindRecordsByFilter(serviceSecretsCollection, filter, "", 0, 0, params)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: listAll service secrets: %w", err)
	}
	out := make([]*ServiceSecret, 0, len(records))
	for _, r := range records {
		ss := recordToServiceSecret(r)
		ss.Value = ""
		out = append(out, ss)
	}
	return out, nil
}

// Versions exposes the underlying secret-version store for read paths.
func (s *ServiceSecretStore) Versions() *SecretVersionStore { return s.versions }

func recordToServiceSecret(r *core.Record) *ServiceSecret {
	ss := &ServiceSecret{
		SecretID:   r.Id,
		ID:         r.Id,
		OrgID:      r.GetString("org_id"),
		TenantID:   r.GetString("org_id"),
		Path:       r.GetString("path"),
		Name:       r.GetString("name"),
		Value:      r.GetString("value"),
		SecretType: r.GetString("secret_type"),
		Status:     r.GetString("status"),
		CreatedAt:  r.GetString("created"),
		UpdatedAt:  r.GetString("updated"),
		RotatedAt:  r.GetString("rotated_at"),
	}
	if raw := r.GetString("metadata"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &ss.Metadata)
	}
	return ss
}
