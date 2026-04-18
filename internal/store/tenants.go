package store

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hanzoai/base/core"
)

const tenantsCollection = "kms_tenants"

// ErrTenantNotFound is returned when a tenant is not found.
var ErrTenantNotFound = errors.New("store: tenant not found")

// ErrTenantExists is returned when a tenant with the same id already exists.
var ErrTenantExists = errors.New("store: tenant already exists")

// Tenant is metadata about a KMS tenant. tenant_id === IAM owner slug.
// KMS does not own identity — it only stores policy/envelope metadata.
type Tenant struct {
	TenantID        string   `json:"tenantId"`
	Name            string   `json:"name"`
	EntityType      string   `json:"entityType"`  // ats | bd | ta | platform
	Environment     string   `json:"environment"` // devnet | testnet | mainnet
	AllowedServices []string `json:"allowedServices,omitempty"`
	AllowedChains   []string `json:"allowedChains,omitempty"`
	CreatedAt       string   `json:"createdAt,omitempty"`
	UpdatedAt       string   `json:"updatedAt,omitempty"`
}

// TenantStore provides CRUD for tenant metadata.
type TenantStore struct {
	app core.App
}

// NewTenantStore creates a tenant store backed by Base.
func NewTenantStore(app core.App) *TenantStore { return &TenantStore{app: app} }

// Create inserts a new tenant. Returns ErrTenantExists if the tenant_id is
// already present.
func (s *TenantStore) Create(t *Tenant) error {
	col, err := s.app.FindCollectionByNameOrId(tenantsCollection)
	if err != nil {
		return fmt.Errorf("store: collection %s: %w", tenantsCollection, err)
	}

	rec := core.NewRecord(col)
	rec.Set("tenant_id", t.TenantID)
	rec.Set("name", t.Name)
	rec.Set("entity_type", t.EntityType)
	rec.Set("environment", t.Environment)
	rec.Set("allowed_services", t.AllowedServices)
	rec.Set("allowed_chains", t.AllowedChains)
	if err := s.app.Save(rec); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrTenantExists
		}
		return fmt.Errorf("store: save tenant: %w", err)
	}
	t.CreatedAt = rec.GetString("created")
	t.UpdatedAt = rec.GetString("updated")
	return nil
}

// Get returns the tenant record by tenant_id.
func (s *TenantStore) Get(tenantID string) (*Tenant, error) {
	rec, err := s.app.FindFirstRecordByFilter(
		tenantsCollection,
		"tenant_id = {:id}",
		map[string]any{"id": tenantID},
	)
	if err != nil {
		return nil, ErrTenantNotFound
	}
	return recordToTenant(rec), nil
}

// List returns tenants matching the optional filters. Empty strings are
// treated as wildcards. Caller is responsible for requiring admin auth.
func (s *TenantStore) List(entityType, environment string) ([]*Tenant, error) {
	var (
		clauses []string
		params  = map[string]any{}
	)
	if entityType != "" {
		clauses = append(clauses, "entity_type = {:et}")
		params["et"] = entityType
	}
	if environment != "" {
		clauses = append(clauses, "environment = {:env}")
		params["env"] = environment
	}
	filter := strings.Join(clauses, " && ")

	records, err := s.app.FindRecordsByFilter(tenantsCollection, filter, "tenant_id", 0, 0, params)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: list tenants: %w", err)
	}
	out := make([]*Tenant, 0, len(records))
	for _, r := range records {
		out = append(out, recordToTenant(r))
	}
	return out, nil
}

// Update mutates an existing tenant. Only Name, AllowedServices, AllowedChains
// are mutable — entity type and environment are set-once at create.
func (s *TenantStore) Update(tenantID, name string, allowedServices, allowedChains []string) (*Tenant, error) {
	rec, err := s.app.FindFirstRecordByFilter(
		tenantsCollection,
		"tenant_id = {:id}",
		map[string]any{"id": tenantID},
	)
	if err != nil {
		return nil, ErrTenantNotFound
	}
	if name != "" {
		rec.Set("name", name)
	}
	if allowedServices != nil {
		rec.Set("allowed_services", allowedServices)
	}
	if allowedChains != nil {
		rec.Set("allowed_chains", allowedChains)
	}
	if err := s.app.Save(rec); err != nil {
		return nil, fmt.Errorf("store: update tenant: %w", err)
	}
	return recordToTenant(rec), nil
}

// Delete removes a tenant by id.
func (s *TenantStore) Delete(tenantID string) error {
	rec, err := s.app.FindFirstRecordByFilter(
		tenantsCollection,
		"tenant_id = {:id}",
		map[string]any{"id": tenantID},
	)
	if err != nil {
		return ErrTenantNotFound
	}
	return s.app.Delete(rec)
}

func recordToTenant(r *core.Record) *Tenant {
	return &Tenant{
		TenantID:        r.GetString("tenant_id"),
		Name:            r.GetString("name"),
		EntityType:      r.GetString("entity_type"),
		Environment:     r.GetString("environment"),
		AllowedServices: stringSlice(r, "allowed_services"),
		AllowedChains:   stringSlice(r, "allowed_chains"),
		CreatedAt:       r.GetString("created"),
		UpdatedAt:       r.GetString("updated"),
	}
}

// stringSlice pulls a JSON array of strings from a Base record.
func stringSlice(r *core.Record, field string) []string {
	raw := r.Get(field)
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		// Best-effort fallback: comma-separated.
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}
