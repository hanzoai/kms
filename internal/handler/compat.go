package handler

import (
	"net/http"
	"strings"
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
// For IAM-based auth the bearer token IS the IAM JWT; echo it back.
func (h *Compat) AuthToken(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
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
	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":               claims.Sub,
			"email":            claims.Email,
			"username":         claims.Email,
			"firstName":        "",
			"lastName":         "",
			"superAdmin":       true,
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
			"id":                      orgSlug,
			"name":                    orgSlug,
			"slug":                    orgSlug,
			"userRole":                "admin",
			"bypassOrgAuthEnabled":    false,
			"authEnforced":            false,
			"googleSsoAuthEnforced":   false,
			"scimEnabled":             false,
			"userJoinedAt":            "2026-01-01T00:00:00Z",
		}},
	})
}

// SelectOrg handles POST /v1/auth/select-organization.
// No real org switching; return the current token.
func (h *Compat) SelectOrg(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"isMfaEnabled": false,
	})
}

// GetOrg handles GET /v1/organization/{orgId}.
func (h *Compat) GetOrg(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgId")
	writeJSON(w, http.StatusOK, map[string]any{
		"organization": map[string]any{
			"id":   orgID,
			"name": orgID,
			"slug": orgID,
		},
	})
}

// OrgSubscription handles GET /v1/organization/{orgId}/subscription.
// Returns an enterprise self-hosted plan stub that enables all features.
func (h *Compat) OrgSubscription(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"plan": map[string]any{
			"id":              "enterprise-self-hosted",
			"tier":            3,
			"slug":            "enterprise",
			"name":            "Enterprise (Self-Hosted)",
			"productId":       "prod_enterprise",
			"workspaceLimit":  0,
			"memberLimit":     0,
			"secretLimit":     0,
			"environmentLimit": 0,
			"dynamicSecret":   true,
			"secretRotation":  true,
			"auditLogs":       true,
			"samlSSO":         true,
			"scim":            true,
			"groups":          true,
			"status":          "active",
			"trial_end":       nil,
			"has_used_trial":  true,
		},
	})
}

// OrgPermissions handles GET /v1/organization/{orgId}/permissions.
// Returns full admin permissions for the authenticated user.
func (h *Compat) OrgPermissions(w http.ResponseWriter, r *http.Request) {
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

// SRPLogin1 handles POST /v1/auth/login1.
// SRP is not used with IAM OIDC auth.
func (h *Compat) SRPLogin1(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "SRP login disabled; use OIDC via hanzo.id")
}

// SRPLogin2 handles POST /v1/auth/login2.
// SRP is not used with IAM OIDC auth.
func (h *Compat) SRPLogin2(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "SRP login disabled; use OIDC via hanzo.id")
}

// StatusEnhanced handles GET /v1/status with Infisical-compatible fields.
func (h *Compat) StatusEnhanced(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"date":    time.Now().UTC().Format(time.RFC3339),
		"message": "Ok",
		"emailConfigured": false,
		"secretScanningConfigured": false,
		"samlDefaultOrgSlug": nil,
		"redisConfigured": false,
	})
}

// allPermissions returns a permission set that grants full access to all
// Infisical resource types. The frontend uses these to decide which UI
// elements to show.
func allPermissions() []map[string]any {
	resources := []string{
		"secrets", "secret-folders", "secret-imports", "secret-rollback",
		"member", "groups", "role", "integrations", "webhooks",
		"service-tokens", "settings", "environments", "tags",
		"audit-logs", "ip-allowlist", "workspace", "identity",
		"certificate-authorities", "certificates", "certificate-templates",
		"pki-alerts", "pki-collections",
		"secret-rotation", "dynamic-secret",
		"kms", "cmek",
	}
	actions := []string{"create", "read", "edit", "delete"}

	rules := make([]map[string]any, 0, len(resources)*len(actions))
	for _, res := range resources {
		for _, act := range actions {
			rules = append(rules, map[string]any{
				"subject": res,
				"action":  act,
			})
		}
	}
	return rules
}
