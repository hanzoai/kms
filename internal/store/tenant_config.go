package store

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hanzoai/base/core"
)

const tenantConfigCollection = "kms_tenant_configs"

// ErrTenantConfigNotFound is returned when a tenant config record is absent.
var ErrTenantConfigNotFound = errors.New("store: tenant config not found")

// TenantConfig holds the arbitrary binding bag plus per-feature flags.
type TenantConfig struct {
	TenantID     string            `json:"tenantId"`
	Bindings     map[string]any    `json:"bindings,omitempty"`
	FeatureFlags map[string]bool   `json:"featureFlags,omitempty"`
	UpdatedAt    string            `json:"updatedAt,omitempty"`
}

// TenantConfigStore provides get/put for tenant configuration.
type TenantConfigStore struct {
	app core.App
}

// NewTenantConfigStore constructs a store.
func NewTenantConfigStore(app core.App) *TenantConfigStore {
	return &TenantConfigStore{app: app}
}

// Get returns the current config for a tenant. Returns ErrTenantConfigNotFound
// if nothing has been written yet — callers can treat that as an empty bag.
func (s *TenantConfigStore) Get(tenantID string) (*TenantConfig, error) {
	rec, err := s.app.FindFirstRecordByFilter(
		tenantConfigCollection,
		"tenant_id = {:id}",
		map[string]any{"id": tenantID},
	)
	if err != nil {
		return nil, ErrTenantConfigNotFound
	}
	return recordToTenantConfig(rec), nil
}

// Put replaces the config for a tenant (upsert).
func (s *TenantConfigStore) Put(cfg *TenantConfig) (*TenantConfig, error) {
	col, err := s.app.FindCollectionByNameOrId(tenantConfigCollection)
	if err != nil {
		return nil, fmt.Errorf("store: collection %s: %w", tenantConfigCollection, err)
	}

	bindingsJSON, _ := json.Marshal(cfg.Bindings)
	flagsJSON, _ := json.Marshal(cfg.FeatureFlags)

	existing, _ := s.app.FindFirstRecordByFilter(
		tenantConfigCollection,
		"tenant_id = {:id}",
		map[string]any{"id": cfg.TenantID},
	)
	if existing != nil {
		existing.Set("bindings", string(bindingsJSON))
		existing.Set("feature_flags", string(flagsJSON))
		if err := s.app.Save(existing); err != nil {
			return nil, fmt.Errorf("store: update tenant config: %w", err)
		}
		return recordToTenantConfig(existing), nil
	}
	rec := core.NewRecord(col)
	rec.Set("tenant_id", cfg.TenantID)
	rec.Set("bindings", string(bindingsJSON))
	rec.Set("feature_flags", string(flagsJSON))
	if err := s.app.Save(rec); err != nil {
		return nil, fmt.Errorf("store: save tenant config: %w", err)
	}
	return recordToTenantConfig(rec), nil
}

func recordToTenantConfig(r *core.Record) *TenantConfig {
	cfg := &TenantConfig{
		TenantID:  r.GetString("tenant_id"),
		UpdatedAt: r.GetString("updated"),
	}
	if raw := r.GetString("bindings"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg.Bindings)
	}
	if raw := r.GetString("feature_flags"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg.FeatureFlags)
	}
	return cfg
}
