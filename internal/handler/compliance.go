package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/store"
)

// Compliance handles audit and compliance endpoints.
type Compliance struct {
	audit *store.AuditStore
}

// NewCompliance creates a compliance handler.
func NewCompliance(a *store.AuditStore) *Compliance {
	return &Compliance{audit: a}
}

// AuditLog returns the WORM audit log for an org.
// GET /v1/orgs/{org}/audit
func (h *Compliance) AuditLog(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
		return
	}

	entries, err := h.audit.List(orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list audit log")
		return
	}
	if entries == nil {
		entries = []*store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}
