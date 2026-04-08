// Package handler implements HTTP handlers for the KMS API.
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/store"
)

// Secrets handles ZK secret CRUD.
// Secrets are encrypted client-side; kmsd stores opaque blobs.
type Secrets struct {
	store *store.SecretStore
}

// NewSecrets creates a secrets handler.
func NewSecrets(s *store.SecretStore) *Secrets {
	return &Secrets{store: s}
}

// Create stores a new encrypted secret.
// POST /v1/orgs/{org}/zk/secrets
func (h *Secrets) Create(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
		return
	}

	var req struct {
		Path       string `json:"path"`
		Name       string `json:"name"`
		Env        string `json:"env,omitempty"`
		Ciphertext string `json:"ciphertext"`
		WrappedDEK string `json:"wrapped_dek"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Path == "" || req.Name == "" || req.Ciphertext == "" || req.WrappedDEK == "" {
		writeError(w, http.StatusBadRequest, "path, name, ciphertext, and wrapped_dek are required")
		return
	}

	sec := &store.Secret{
		OrgID:      orgID,
		Path:       req.Path,
		Name:       req.Name,
		Env:        req.Env,
		Ciphertext: req.Ciphertext,
		WrappedDEK: req.WrappedDEK,
	}
	if err := h.store.Create(sec); err != nil {
		if err == store.ErrSecretExists {
			writeError(w, http.StatusConflict, "secret already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to store secret")
		return
	}
	writeJSON(w, http.StatusCreated, sec)
}

// Get retrieves an encrypted secret.
// GET /v1/orgs/{org}/zk/secrets/{path}/{name}
func (h *Secrets) Get(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, sec)
}

// Delete removes an encrypted secret.
// DELETE /v1/orgs/{org}/zk/secrets/{path}/{name}
func (h *Secrets) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
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

// List returns all encrypted secret names for an org.
// GET /v1/orgs/{org}/zk/secrets
func (h *Secrets) List(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
		return
	}

	secrets, err := h.store.List(orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list secrets")
		return
	}
	if secrets == nil {
		secrets = []*store.Secret{}
	}
	writeJSON(w, http.StatusOK, secrets)
}

// requireOrg checks that the JWT owner matches the requested org.
func requireOrg(r *http.Request, orgID string) error {
	claims := auth.FromContext(r.Context())
	if claims == nil || claims.Owner != orgID {
		return errForbidden
	}
	return nil
}
