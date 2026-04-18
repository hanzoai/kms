package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/store"
)

// Integrations handles tenant-scoped integration bindings at
// /v1/kms/tenants/{tenantId}/integrations.
type Integrations struct {
	store *store.IntegrationStore
	audit *store.AuditStore
}

// NewIntegrations builds an integrations handler.
func NewIntegrations(s *store.IntegrationStore, a *store.AuditStore) *Integrations {
	return &Integrations{store: s, audit: a}
}

// requireTenant enforces tenant ownership (or admin) for every integration op.
func requireTenant(claims *auth.Claims, tenantID string) bool {
	if isAdmin(claims) {
		return true
	}
	return claims != nil && claims.Owner == tenantID
}

// List returns bindings for a tenant.
// GET /v1/kms/tenants/{tenantId}/integrations?provider=
func (h *Integrations) List(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	claims := auth.FromContext(r.Context())
	if !requireTenant(claims, tenantID) {
		writeError(w, http.StatusForbidden, "tenant mismatch")
		return
	}
	items, err := h.store.List(tenantID, r.URL.Query().Get("provider"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list integrations")
		return
	}
	if items == nil {
		items = []*store.Integration{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// Create binds a new integration.
// POST /v1/kms/tenants/{tenantId}/integrations
func (h *Integrations) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	claims := auth.FromContext(r.Context())
	if !requireTenant(claims, tenantID) {
		writeError(w, http.StatusForbidden, "tenant mismatch")
		return
	}

	var req struct {
		Provider   string         `json:"provider"`
		Status     string         `json:"status,omitempty"`
		SecretRefs []string       `json:"secretRefs,omitempty"`
		Config     map[string]any `json:"config,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Provider == "" {
		writeError(w, http.StatusBadRequest, "provider is required")
		return
	}

	it, err := h.store.Create(&store.Integration{
		TenantID:   tenantID,
		Provider:   req.Provider,
		Status:     req.Status,
		SecretRefs: req.SecretRefs,
		Config:     req.Config,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create integration")
		return
	}
	_ = h.audit.Append(tenantID, map[string]any{
		"actor_id":     claimSub(claims),
		"action":       "integration.create",
		"subject_id":   it.IntegrationID,
		"subject_type": "integration",
	})
	writeJSON(w, http.StatusCreated, it)
}
