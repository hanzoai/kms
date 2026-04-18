package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
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

// Query returns filtered audit entries.
// GET /v1/kms/audit?tenantId=&actorId=&subjectId=&action=&since=&until=&page=&perPage=
// Non-admins may only query their own tenant; admins may omit tenantId for
// cross-tenant reads.
func (h *Compliance) Query(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	q := store.AuditQuery{
		TenantID:  r.URL.Query().Get("tenantId"),
		ActorID:   r.URL.Query().Get("actorId"),
		SubjectID: r.URL.Query().Get("subjectId"),
		Action:    r.URL.Query().Get("action"),
		Since:     r.URL.Query().Get("since"),
		Until:     r.URL.Query().Get("until"),
	}
	if v := r.URL.Query().Get("page"); v != "" {
		q.Page, _ = strconv.Atoi(v)
	}
	if v := r.URL.Query().Get("perPage"); v != "" {
		q.PerPage, _ = strconv.Atoi(v)
	}

	if !isAdmin(claims) {
		if claims == nil || claims.Owner == "" {
			writeError(w, http.StatusForbidden, "owner claim required")
			return
		}
		if q.TenantID != "" && q.TenantID != claims.Owner {
			writeError(w, http.StatusForbidden, "tenant mismatch")
			return
		}
		q.TenantID = claims.Owner
	}

	entries, total, err := h.audit.Query(q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query audit log")
		return
	}
	if entries == nil {
		entries = []*store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":      entries,
		"page":       q.Page,
		"totalItems": total,
	})
}
