package handler

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/store"
)

// ServiceSecrets handles server-side encrypted secret CRUD for service-to-service use.
// Unlike ZK secrets, these are decrypted by the KMS server and returned as plaintext
// to authenticated callers. Auth is via IAM JWT (service account).
type ServiceSecrets struct {
	store *store.ServiceSecretStore
}

// NewServiceSecrets creates a service secrets handler.
func NewServiceSecrets(s *store.ServiceSecretStore) *ServiceSecrets {
	return &ServiceSecrets{store: s}
}

// Put creates or updates a service secret.
// PUT /v1/kms/orgs/{org}/secrets/{path}/{name}
func (h *ServiceSecrets) Put(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
		return
	}

	path := chi.URLParam(r, "path")
	name := chi.URLParam(r, "name")
	if path == "" || name == "" {
		writeError(w, http.StatusBadRequest, "path and name are required")
		return
	}

	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}

	// Require admin role for writes.
	claims := auth.FromContext(r.Context())
	if claims == nil || !hasAdminRole(claims) {
		writeError(w, http.StatusForbidden, "admin role required for secret writes")
		return
	}

	sec := &store.ServiceSecret{
		OrgID: orgID,
		Path:  path,
		Name:  name,
		Value: req.Value,
	}
	if err := h.store.Put(sec); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path": sec.Path,
		"name": sec.Name,
	})
}

// Get retrieves a service secret value.
// GET /v1/kms/orgs/{org}/secrets/{path}/{name}
func (h *ServiceSecrets) Get(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
		return
	}

	path := chi.URLParam(r, "path")
	name := chi.URLParam(r, "name")

	sec, err := h.store.Get(orgID, path, name)
	if err != nil {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": map[string]any{
			"path":  sec.Path,
			"name":  sec.Name,
			"value": sec.Value,
		},
	})
}

// Delete removes a service secret.
// DELETE /v1/kms/orgs/{org}/secrets/{path}/{name}
func (h *ServiceSecrets) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
		return
	}

	// Require admin role for deletes.
	claims := auth.FromContext(r.Context())
	if claims == nil || !hasAdminRole(claims) {
		writeError(w, http.StatusForbidden, "admin role required for secret deletes")
		return
	}

	path := chi.URLParam(r, "path")
	name := chi.URLParam(r, "name")

	if err := h.store.Delete(orgID, path, name); err != nil {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// List returns secret names (no values) for an org.
// GET /v1/kms/orgs/{org}/secrets
func (h *ServiceSecrets) List(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	secrets, err := h.store.List(orgID, prefix)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list secrets")
		return
	}
	if secrets == nil {
		secrets = []*store.ServiceSecret{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secrets": secrets,
	})
}

// hasAdminRole checks if claims contain an admin-level role.
func hasAdminRole(claims *auth.Claims) bool {
	for _, r := range claims.Roles {
		switch r {
		case "admin", "owner", "superadmin":
			return true
		}
	}
	if os.Getenv("KMS_SINGLE_TENANT_ADMIN") == "true" {
		return true
	}
	return false
}
