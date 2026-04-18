package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/store"
)

// Tenants handles tenant CRUD at /v1/kms/tenants.
// Tenant identity is owned by IAM — `tenantId` === JWT `owner`. KMS only
// stores tenant metadata (entityType, environment, allowedServices,
// allowedChains).
type Tenants struct {
	store *store.TenantStore
	audit *store.AuditStore
}

// NewTenants builds a tenants handler.
func NewTenants(s *store.TenantStore, a *store.AuditStore) *Tenants {
	return &Tenants{store: s, audit: a}
}

// List returns tenants. Requires kms.admin for cross-tenant visibility.
// Non-admins only see their own tenant (single item).
// GET /v1/kms/tenants
func (h *Tenants) List(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	entityType := r.URL.Query().Get("entityType")
	environment := r.URL.Query().Get("environment")

	if !isAdmin(claims) {
		if claims == nil || claims.Owner == "" {
			writeError(w, http.StatusForbidden, "owner claim required")
			return
		}
		t, err := h.store.Get(claims.Owner)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"items":      []any{},
				"page":       1,
				"totalItems": 0,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items":      []*store.Tenant{t},
			"page":       1,
			"totalItems": 1,
		})
		return
	}

	tenants, err := h.store.List(entityType, environment)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tenants")
		return
	}
	if tenants == nil {
		tenants = []*store.Tenant{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":      tenants,
		"page":       1,
		"totalItems": len(tenants),
	})
}

// Create makes a new tenant. Admin-only. Body must include tenantId; path
// has no tenantId.
// POST /v1/kms/tenants
func (h *Tenants) Create(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	if !isAdmin(claims) {
		writeError(w, http.StatusForbidden, "kms.admin role required")
		return
	}

	var req store.Tenant
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TenantID == "" || req.Name == "" || req.EntityType == "" || req.Environment == "" {
		writeError(w, http.StatusBadRequest, "tenantId, name, entityType, environment are required")
		return
	}
	if err := h.store.Create(&req); err != nil {
		if errors.Is(err, store.ErrTenantExists) {
			writeError(w, http.StatusConflict, "tenant already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create tenant")
		return
	}

	_ = h.audit.Append(req.TenantID, map[string]any{
		"actor_id":     claimSub(claims),
		"action":       "tenant.create",
		"subject_id":   req.TenantID,
		"subject_type": "tenant",
		"ip":           r.RemoteAddr,
		"user_agent":   r.UserAgent(),
	})

	writeJSON(w, http.StatusCreated, req)
}

// Get returns one tenant. Caller must be admin or equal to tenant.
// GET /v1/kms/tenants/{tenantId}
func (h *Tenants) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	claims := auth.FromContext(r.Context())
	if !isAdmin(claims) && (claims == nil || claims.Owner != tenantID) {
		writeError(w, http.StatusForbidden, "tenant mismatch")
		return
	}
	t, err := h.store.Get(tenantID)
	if err != nil {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// Update patches a tenant. Admin only.
// PATCH /v1/kms/tenants/{tenantId}
func (h *Tenants) Update(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	if !isAdmin(claims) {
		writeError(w, http.StatusForbidden, "kms.admin role required")
		return
	}
	tenantID := chi.URLParam(r, "tenantId")

	var req struct {
		Name            string   `json:"name"`
		AllowedServices []string `json:"allowedServices"`
		AllowedChains   []string `json:"allowedChains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	out, err := h.store.Update(tenantID, req.Name, req.AllowedServices, req.AllowedChains)
	if err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to update tenant")
		return
	}
	_ = h.audit.Append(tenantID, map[string]any{
		"actor_id":     claimSub(claims),
		"action":       "tenant.update",
		"subject_id":   tenantID,
		"subject_type": "tenant",
	})
	writeJSON(w, http.StatusOK, out)
}

// Delete removes a tenant. Admin only.
// DELETE /v1/kms/tenants/{tenantId}
func (h *Tenants) Delete(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	if !isAdmin(claims) {
		writeError(w, http.StatusForbidden, "kms.admin role required")
		return
	}
	tenantID := chi.URLParam(r, "tenantId")
	if err := h.store.Delete(tenantID); err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete tenant")
		return
	}
	_ = h.audit.Append(tenantID, map[string]any{
		"actor_id":     claimSub(claims),
		"action":       "tenant.delete",
		"subject_id":   tenantID,
		"subject_type": "tenant",
	})
	w.WriteHeader(http.StatusNoContent)
}

// claimSub pulls the subject from claims for audit attribution.
func claimSub(c *auth.Claims) string {
	if c == nil {
		return ""
	}
	return c.Sub
}
