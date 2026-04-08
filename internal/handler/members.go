package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/store"
)

// Members handles org member management.
type Members struct {
	store *store.MemberStore
}

// NewMembers creates a members handler.
func NewMembers(s *store.MemberStore) *Members {
	return &Members{store: s}
}

// Create registers a new member for an org.
// POST /v1/orgs/{org}/members
func (h *Members) Create(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
		return
	}

	var req struct {
		MemberID   string `json:"member_id"`
		PubKey     string `json:"pub_key"`
		WrappedCEK string `json:"wrapped_cek"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.MemberID == "" || req.PubKey == "" || req.WrappedCEK == "" {
		writeError(w, http.StatusBadRequest, "member_id, pub_key, and wrapped_cek are required")
		return
	}

	m := &store.Member{
		OrgID:      orgID,
		MemberID:   req.MemberID,
		PubKey:     req.PubKey,
		WrappedCEK: req.WrappedCEK,
	}
	if err := h.store.Create(m); err != nil {
		if err == store.ErrMemberExists {
			writeError(w, http.StatusConflict, "member already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to store member")
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

// List returns all members for an org.
// GET /v1/orgs/{org}/members
func (h *Members) List(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
		return
	}

	members, err := h.store.List(orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list members")
		return
	}
	if members == nil {
		members = []*store.Member{}
	}
	writeJSON(w, http.StatusOK, members)
}

// Delete removes a member from an org.
// DELETE /v1/orgs/{org}/members/{memberID}
func (h *Members) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org")
	if err := requireOrg(r, orgID); err != nil {
		writeError(w, http.StatusForbidden, "org mismatch")
		return
	}
	memberID := chi.URLParam(r, "memberID")

	if err := h.store.Delete(orgID, memberID); err != nil {
		writeError(w, http.StatusNotFound, "member not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
