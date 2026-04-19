package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/store"
)

// TenantSecrets serves the spec-shaped, tenant-scoped secret surface at
// /v1/kms/tenants/{tenantId}/secrets. This is the one and only write surface
// for service secrets; reads/updates/deletes go through /v1/kms/secrets/{id}.
type TenantSecrets struct {
	store *store.ServiceSecretStore
	audit *store.AuditStore
}

// NewTenantSecrets builds a handler.
func NewTenantSecrets(s *store.ServiceSecretStore, a *store.AuditStore) *TenantSecrets {
	return &TenantSecrets{store: s, audit: a}
}

// List returns metadata-only for a tenant's secrets.
// GET /v1/kms/tenants/{tenantId}/secrets?secretType=
//
// R2-4: requires canReadSecret. Plain tenant membership is insufficient —
// a tenant member without the kms.secret.read role could otherwise enumerate
// every secret ID, which is itself sensitive metadata.
func (h *TenantSecrets) List(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	claims := auth.FromContext(r.Context())
	if !canReadSecret(claims, tenantID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	q := r.URL.Query()
	items, err := h.store.ListAll(tenantID, q.Get("secretType"), q.Get("path"), q.Get("name"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list secrets")
		return
	}
	if items == nil {
		items = []*store.ServiceSecret{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// Create stores a new tenant secret and returns the persisted metadata,
// including the canonical secretId.
// POST /v1/kms/tenants/{tenantId}/secrets
func (h *TenantSecrets) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	claims := auth.FromContext(r.Context())
	if !requireTenant(claims, tenantID) {
		writeError(w, http.StatusForbidden, "tenant mismatch")
		return
	}
	if !isSecretAdmin(claims, tenantID) {
		writeError(w, http.StatusForbidden, "admin role required for secret writes")
		return
	}

	var req struct {
		Path       string            `json:"path"`
		Name       string            `json:"name"`
		Value      string            `json:"value"`
		SecretType string            `json:"secretType,omitempty"`
		Metadata   map[string]string `json:"metadata,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Path == "" || req.Name == "" || req.Value == "" {
		writeError(w, http.StatusBadRequest, "path, name, value are required")
		return
	}

	sec := &store.ServiceSecret{
		OrgID:      tenantID,
		Path:       req.Path,
		Name:       req.Name,
		Value:      req.Value,
		SecretType: req.SecretType,
		Metadata:   req.Metadata,
	}
	if err := h.store.Put(sec); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store secret")
		return
	}
	_ = h.audit.Append(tenantID, map[string]any{
		"actor_id":     claimSub(claims),
		"action":       "secret.create",
		"subject_id":   sec.SecretID,
		"subject_type": "secret",
	})
	// Redact the value in the response — fetch via GET by id.
	sec.Value = ""
	writeJSON(w, http.StatusCreated, sec)
}
