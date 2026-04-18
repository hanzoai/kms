package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hanzoai/base/core"
)

const integrationsCollection = "kms_integrations"

// ErrIntegrationNotFound is returned when an integration binding is missing.
var ErrIntegrationNotFound = errors.New("store: integration not found")

// Integration is a per-tenant provider binding (alpaca, kraken, braintree,
// plaid, chainalysis, ...). `secret_refs` points at secretIds managed by
// this KMS for credential material.
type Integration struct {
	IntegrationID string         `json:"integrationId"`
	TenantID      string         `json:"tenantId"`
	Provider      string         `json:"provider"`
	Status        string         `json:"status"` // active | disabled | error
	SecretRefs    []string       `json:"secretRefs,omitempty"`
	Config        map[string]any `json:"config,omitempty"`
	CreatedAt     string         `json:"createdAt,omitempty"`
}

// IntegrationStore provides CRUD for integration bindings.
type IntegrationStore struct {
	app core.App
}

// NewIntegrationStore constructs a store.
func NewIntegrationStore(app core.App) *IntegrationStore {
	return &IntegrationStore{app: app}
}

// Create binds a new integration.
func (s *IntegrationStore) Create(i *Integration) (*Integration, error) {
	col, err := s.app.FindCollectionByNameOrId(integrationsCollection)
	if err != nil {
		return nil, fmt.Errorf("store: collection %s: %w", integrationsCollection, err)
	}

	cfgJSON, _ := json.Marshal(i.Config)
	rec := core.NewRecord(col)
	rec.Set("tenant_id", i.TenantID)
	rec.Set("provider", i.Provider)
	status := i.Status
	if status == "" {
		status = "active"
	}
	rec.Set("status", status)
	rec.Set("secret_refs", i.SecretRefs)
	rec.Set("config", string(cfgJSON))
	if err := s.app.Save(rec); err != nil {
		return nil, fmt.Errorf("store: save integration: %w", err)
	}
	return recordToIntegration(rec), nil
}

// List returns integrations for a tenant, optionally filtered by provider.
func (s *IntegrationStore) List(tenantID, provider string) ([]*Integration, error) {
	filter := "tenant_id = {:tid}"
	params := map[string]any{"tid": tenantID}
	if provider != "" {
		filter += " && provider = {:prov}"
		params["prov"] = provider
	}
	records, err := s.app.FindRecordsByFilter(integrationsCollection, filter, "created", 0, 0, params)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: list integrations: %w", err)
	}
	out := make([]*Integration, 0, len(records))
	for _, r := range records {
		out = append(out, recordToIntegration(r))
	}
	return out, nil
}

// Get returns a single integration by id.
func (s *IntegrationStore) Get(tenantID, integrationID string) (*Integration, error) {
	rec, err := s.app.FindRecordById(integrationsCollection, integrationID)
	if err != nil {
		return nil, ErrIntegrationNotFound
	}
	if rec.GetString("tenant_id") != tenantID {
		return nil, ErrIntegrationNotFound
	}
	return recordToIntegration(rec), nil
}

// Delete removes an integration binding.
func (s *IntegrationStore) Delete(tenantID, integrationID string) error {
	rec, err := s.app.FindRecordById(integrationsCollection, integrationID)
	if err != nil {
		return ErrIntegrationNotFound
	}
	if rec.GetString("tenant_id") != tenantID {
		return ErrIntegrationNotFound
	}
	return s.app.Delete(rec)
}

func recordToIntegration(r *core.Record) *Integration {
	i := &Integration{
		IntegrationID: r.Id,
		TenantID:      r.GetString("tenant_id"),
		Provider:      r.GetString("provider"),
		Status:        r.GetString("status"),
		SecretRefs:    stringSlice(r, "secret_refs"),
		CreatedAt:     r.GetString("created"),
	}
	if raw := r.GetString("config"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &i.Config)
	}
	return i
}
