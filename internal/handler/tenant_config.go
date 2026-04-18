package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/store"
)

// TenantConfig handles GET/PUT /v1/kms/tenants/{tenantId}/config.
type TenantConfig struct {
	store *store.TenantConfigStore
	audit *store.AuditStore
}

// NewTenantConfig builds a handler.
func NewTenantConfig(s *store.TenantConfigStore, a *store.AuditStore) *TenantConfig {
	return &TenantConfig{store: s, audit: a}
}

// Get returns the current config. Accessible to the tenant owner or admin.
func (h *TenantConfig) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	claims := auth.FromContext(r.Context())
	if !isAdmin(claims) && (claims == nil || claims.Owner != tenantID) {
		writeError(w, http.StatusForbidden, "tenant mismatch")
		return
	}
	cfg, err := h.store.Get(tenantID)
	if err != nil {
		if errors.Is(err, store.ErrTenantConfigNotFound) {
			writeJSON(w, http.StatusOK, &store.TenantConfig{TenantID: tenantID})
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get tenant config")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// Put replaces the config. Admin-only for writes.
func (h *TenantConfig) Put(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	claims := auth.FromContext(r.Context())
	if !isAdmin(claims) && (claims == nil || claims.Owner != tenantID) {
		writeError(w, http.StatusForbidden, "tenant mismatch")
		return
	}
	if !isAdmin(claims) {
		writeError(w, http.StatusForbidden, "kms.admin role required to write config")
		return
	}

	var req store.TenantConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.TenantID = tenantID

	out, err := h.store.Put(&req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write tenant config")
		return
	}
	_ = h.audit.Append(tenantID, map[string]any{
		"actor_id":     claimSub(claims),
		"action":       "tenant.config.update",
		"subject_id":   tenantID,
		"subject_type": "tenant",
	})
	writeJSON(w, http.StatusOK, out)
}
