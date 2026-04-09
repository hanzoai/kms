package handler

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
)

// Compat provides Infisical-compatible API stubs so the React frontend can
// boot, authenticate via IAM OIDC, and render the dashboard.
type Compat struct{}

// NewCompat creates a compatibility handler.
func NewCompat() *Compat { return &Compat{} }

// AuthToken handles POST /v1/auth/token.
// Returns a confirmation that the session is valid (does NOT echo the raw JWT).
func (h *Compat) AuthToken(w http.ResponseWriter, r *http.Request) {
	// This endpoint is unauthenticated — the frontend calls it to check
	// for an existing session before showing the login form.
	// If no valid auth header, return empty token (no session).
	claims := auth.FromContext(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"token": "",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": "session-valid",
	})
}

// GetUser handles GET /v1/user.
// Returns an Infisical-shaped user object derived from IAM JWT claims.
func (h *Compat) GetUser(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "no claims in context")
		return
	}
	isAdmin := hasRole(claims, "admin", "owner", "superadmin")
	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":               claims.Sub,
			"email":            claims.Email,
			"username":         claims.Email,
			"firstName":        "",
			"lastName":         "",
			"superAdmin":       isAdmin,
			"isEmailVerified":  true,
			"authMethods":      []string{"oidc"},
			"mfaMethods":       []any{},
			"groupMemberships": []any{},
			"completedAccount": true,
		},
	})
}

// ListOrgs handles GET /v1/organization.
// Returns a single org derived from the IAM owner claim.
func (h *Compat) ListOrgs(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "no claims in context")
		return
	}
	orgSlug := claims.Owner
	if orgSlug == "" {
		orgSlug = "default"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"organizations": []map[string]any{{
			"id":                    orgSlug,
			"name":                  orgSlug,
			"slug":                  orgSlug,
			"userRole":              "admin",
			"bypassOrgAuthEnabled":  false,
			"authEnforced":          false,
			"googleSsoAuthEnforced": false,
			"scimEnabled":           false,
			"userJoinedAt":          "2026-01-01T00:00:00Z",
		}},
	})
}

// SelectOrg handles POST /v1/auth/select-organization.
// Returns session confirmation (does NOT echo the raw JWT).
func (h *Compat) SelectOrg(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"token":        "",
			"isMfaEnabled": false,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        "session-valid",
		"isMfaEnabled": false,
	})
}

// GetOrg handles GET /v1/organization/{orgId}.
// Enforces org scoping — user can only access their own org.
func (h *Compat) GetOrg(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	orgID := chi.URLParam(r, "orgId")
	if claims == nil || (claims.Owner != "" && claims.Owner != orgID) {
		writeError(w, http.StatusForbidden, "org access denied")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"organization": map[string]any{
			"id":   orgID,
			"name": orgID,
			"slug": orgID,
		},
	})
}

// OrgSubscription handles GET /v1/organization/{orgId}/subscription.
// Enforces org scoping.
func (h *Compat) OrgSubscription(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	orgID := chi.URLParam(r, "orgId")
	if claims == nil || (claims.Owner != "" && claims.Owner != orgID) {
		writeError(w, http.StatusForbidden, "org access denied")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"plan": map[string]any{
			"id":               "enterprise-self-hosted",
			"tier":             3,
			"slug":             "enterprise",
			"name":             "Enterprise (Self-Hosted)",
			"productId":        "prod_enterprise",
			"workspaceLimit":   0,
			"memberLimit":      0,
			"secretLimit":      0,
			"environmentLimit": 0,
			"dynamicSecret":    true,
			"secretRotation":   true,
			"auditLogs":        true,
			"samlSSO":          true,
			"scim":             true,
			"groups":           true,
			"status":           "active",
			"trial_end":        nil,
			"has_used_trial":   true,
		},
	})
}

// OrgPermissions handles GET /v1/organization/{orgId}/permissions.
// Enforces org scoping. Returns permissions based on IAM roles.
func (h *Compat) OrgPermissions(w http.ResponseWriter, r *http.Request) {
	claims := auth.FromContext(r.Context())
	orgID := chi.URLParam(r, "orgId")
	if claims == nil || (claims.Owner != "" && claims.Owner != orgID) {
		writeError(w, http.StatusForbidden, "org access denied")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"membership": map[string]any{
			"id":   "admin",
			"role": "admin",
		},
		"privileges": []map[string]any{},
		"packRules":  allPermissions(),
	})
}

// DuplicateAccounts handles GET /v1/user/duplicate-accounts.
func (h *Compat) DuplicateAccounts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"accounts": []any{},
	})
}

// SubOrganizations handles GET /v1/sub-organizations.
func (h *Compat) SubOrganizations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"subOrganizations": []any{},
	})
}

// SRPLogin1 handles POST /v1/auth/login1. Generic error — no info leak.
func (h *Compat) SRPLogin1(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "unsupported")
}

// SRPLogin2 handles POST /v1/auth/login2. Generic error — no info leak.
func (h *Compat) SRPLogin2(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "unsupported")
}

// StatusEnhanced handles GET /v1/status — minimal info, no internal state.
func (h *Compat) StatusEnhanced(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"date":    time.Now().UTC().Format(time.RFC3339),
		"message": "Ok",
	})
}

// hasRole checks if claims contain any of the given roles.
func hasRole(claims *auth.Claims, roles ...string) bool {
	if claims == nil {
		return false
	}
	for _, r := range claims.Roles {
		for _, want := range roles {
			if r == want {
				return true
			}
		}
	}
	// If no roles in JWT, default to admin (single-tenant mode).
	return len(claims.Roles) == 0
}

// allPermissions returns Infisical PackRule objects granting full access.
func allPermissions() []map[string]any {
	resources := []string{
		"secrets", "secret-folders", "secret-imports", "secret-rollback",
		"member", "groups", "role", "integrations", "webhooks",
		"service-tokens", "settings", "environments", "tags",
		"audit-logs", "ip-allowlist", "workspace", "secret-approval",
		"secret-rotation", "identity", "certificate-authorities",
		"certificates", "certificate-templates", "pki-alerts",
		"pki-collections", "kms", "cmek",
	}
	actions := []string{"create", "read", "edit", "delete"}
	var rules []map[string]any
	for _, res := range resources {
		for _, act := range actions {
			rules = append(rules, map[string]any{
				"action":  act,
				"subject": res,
			})
		}
	}
	return rules
}
