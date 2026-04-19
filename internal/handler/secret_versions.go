package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/store"
)

// SecretsByID handles the cross-tenant addressable secret surface at
// /v1/kms/secrets/{secretId}. Values are plaintext over TLS (the KMS decrypts
// on read); callers still must present a valid JWT tied to the owning tenant
// (or hold `kms.admin`).
type SecretsByID struct {
	store    *store.ServiceSecretStore
	versions *store.SecretVersionStore
	audit    *store.AuditStore
	idem     *store.IdempotencyStore
}

// NewSecretsByID builds a handler.
func NewSecretsByID(s *store.ServiceSecretStore, a *store.AuditStore, i *store.IdempotencyStore) *SecretsByID {
	return &SecretsByID{store: s, versions: s.Versions(), audit: a, idem: i}
}

// canRead authorizes read access — global admin, tenant secret admin, or a
// tenant member with kms.secret.read (F7).
func (h *SecretsByID) canRead(claims *auth.Claims, tenantID string) bool {
	return canReadSecret(claims, tenantID)
}

// canWrite authorizes mutation — global admin or tenant secret admin. Regular
// tenant members, including those with kms.secret.read, may NOT mutate.
func (h *SecretsByID) canWrite(claims *auth.Claims, tenantID string) bool {
	return isSecretAdmin(claims, tenantID)
}

// ListAll is the admin listing — GET /v1/kms/secrets?tenantId=&secretType=.
func (h *SecretsByID) ListAll(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	tenantID := r.URL.Query().Get("tenantId")
	secretType := r.URL.Query().Get("secretType")

	// Non-admins can only query their own tenant.
	if !isAdmin(claims) {
		if claims == nil || claims.Owner == "" {
			writeError(w, http.StatusForbidden, "owner claim required")
			return
		}
		if tenantID != "" && tenantID != claims.Owner {
			writeError(w, http.StatusForbidden, "tenant mismatch")
			return
		}
		tenantID = claims.Owner
	}

	items, err := h.store.ListAll(tenantID, secretType, "", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list secrets")
		return
	}
	if items == nil {
		items = []*store.ServiceSecret{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// Read returns the current value — GET /v1/kms/secrets/{secretId}.
func (h *SecretsByID) Read(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "secretId")
	claims := auth.FromContext(r.Context())

	sec, err := h.store.GetByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if !h.canRead(claims, sec.TenantID) {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	_ = h.audit.Append(sec.TenantID, map[string]any{
		"actor_id":     claimSub(claims),
		"action":       "secret.read",
		"subject_id":   sec.SecretID,
		"subject_type": "secret",
	})

	writeJSON(w, http.StatusOK, sec)
}

// Update patches the secret and appends a new version — PATCH /v1/kms/secrets/{secretId}.
func (h *SecretsByID) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "secretId")
	claims := auth.FromContext(r.Context())

	sec, err := h.store.GetByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if !h.canWrite(claims, sec.TenantID) {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Value    string            `json:"value"`
		Metadata map[string]string `json:"metadata,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}

	out, err := h.store.Update(id, req.Value, req.Metadata)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update secret")
		return
	}
	_ = h.audit.Append(sec.TenantID, map[string]any{
		"actor_id":     claimSub(claims),
		"action":       "secret.update",
		"subject_id":   id,
		"subject_type": "secret",
	})
	writeJSON(w, http.StatusOK, out)
}

// Delete removes the secret — DELETE /v1/kms/secrets/{secretId}.
func (h *SecretsByID) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "secretId")
	claims := auth.FromContext(r.Context())

	sec, err := h.store.GetByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if !h.canWrite(claims, sec.TenantID) {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.store.DeleteByID(id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete secret")
		return
	}
	_ = h.audit.Append(sec.TenantID, map[string]any{
		"actor_id":     claimSub(claims),
		"action":       "secret.delete",
		"subject_id":   id,
		"subject_type": "secret",
	})
	w.WriteHeader(http.StatusNoContent)
}

// Versions lists the version history — GET /v1/kms/secrets/{secretId}/versions.
func (h *SecretsByID) Versions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "secretId")
	claims := auth.FromContext(r.Context())

	sec, err := h.store.GetByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if !h.canRead(claims, sec.TenantID) {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	versions, err := h.versions.List(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list versions")
		return
	}
	if versions == nil {
		versions = []*store.SecretVersion{}
	}
	// Redact values in listings.
	for _, v := range versions {
		v.Value = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": versions})
}

// Rotate appends a new version — POST /v1/kms/secrets/{secretId}/rotate.
// Idempotent on the Idempotency-Key header: a repeated rotate with the same
// key is a no-op that returns the current version.
func (h *SecretsByID) Rotate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "secretId")
	claims := auth.FromContext(r.Context())

	sec, err := h.store.GetByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if !h.canWrite(claims, sec.TenantID) {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// R2-7: idempotency key is scoped by (tenantID, secretID, rawKey) and
	// claimed atomically via a DB UNIQUE index. Concurrent requests with the
	// same scoped key: only one claims (possibly on a different replica), the
	// rest get the already-rotated current version. TTL is 24h.
	rawKey := r.Header.Get("Idempotency-Key")
	if rawKey != "" {
		scopedKey := store.BuildScopedKey(sec.TenantID, id, rawKey)
		first, err := h.idem.Claim(scopedKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "idempotency claim failed")
			return
		}
		if !first {
			cur, _ := h.versions.Current(id)
			writeJSON(w, http.StatusOK, map[string]any{
				"secretId": id,
				"version":  cur.Version,
				"rotated":  false,
			})
			return
		}
	}

	var req struct {
		NewValue string `json:"newValue,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	newVal := req.NewValue
	if newVal == "" {
		// Service-generated rotation: use existing value as a placeholder.
		// Callers should provide a value; empty signals "let the backing
		// secret type decide". For generic secrets we refuse.
		writeError(w, http.StatusBadRequest, "newValue is required for generic secrets")
		return
	}

	out, ver, err := h.store.Rotate(id, newVal)
	if err != nil {
		if errors.Is(err, store.ErrServiceSecretNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to rotate secret")
		return
	}
	_ = h.audit.Append(sec.TenantID, map[string]any{
		"actor_id":     claimSub(claims),
		"action":       "secret.rotate",
		"subject_id":   id,
		"subject_type": "secret",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"secretId": out.SecretID,
		"version":  ver,
		"rotated":  true,
	})
}
