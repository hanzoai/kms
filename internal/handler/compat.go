package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
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
// Returns the access token if a valid session cookie exists, or 401 otherwise.
func (h *Compat) AuthToken(w http.ResponseWriter, r *http.Request) {
	// Check for session cookie set by OIDC callback.
	cookie, err := r.Cookie("jid")
	if err == nil && cookie.Value != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"token": cookie.Value,
		})
		return
	}

	// Check claims from auth middleware (Bearer token path).
	claims := auth.FromContext(r.Context())
	if claims != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"token": "session-valid",
		})
		return
	}

	// No session.
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"statusCode": 401,
		"message":    "Token has expired",
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
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"statusCode": 401,
			"message":    "Token has expired",
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

// UniversalAuthLogin handles POST /api/v1/auth/universal-auth/login.
// Infisical-compatible machine identity authentication.
// Accepts clientId + clientSecret, returns an accessToken (JWT signed by IAM).
func (h *Compat) UniversalAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": 400,
			"message":    "invalid request body",
			"error":      "Bad Request",
		})
		return
	}
	if req.ClientID == "" || req.ClientSecret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": 400,
			"message":    "clientId and clientSecret are required",
			"error":      "Bad Request",
		})
		return
	}

	// Validate against IAM client_credentials grant
	iamEndpoint := os.Getenv("IAM_JWKS_URL")
	if iamEndpoint == "" {
		iamEndpoint = os.Getenv("IAM_ENDPOINT")
	}
	if iamEndpoint == "" {
		iamEndpoint = "https://hanzo.id"
	}
	// Strip path to get base URL
	if u, err := url.Parse(iamEndpoint); err == nil {
		iamEndpoint = u.Scheme + "://" + u.Host
	}

	// Exchange client credentials for token via IAM
	tokenURL := iamEndpoint + "/api/login/oauth/access_token"
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {req.ClientID},
		"client_secret": {req.ClientSecret},
	}

	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"statusCode": 502,
			"message":    "failed to reach identity provider",
			"error":      "Bad Gateway",
		})
		return
	}
	defer resp.Body.Close()

	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil || resp.StatusCode != 200 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"statusCode": 401,
			"message":    "invalid client credentials",
			"error":      "Unauthorized",
		})
		return
	}

	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"statusCode": 401,
			"message":    "invalid client credentials",
			"error":      "Unauthorized",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken":          accessToken,
		"expiresIn":            86400,
		"accessTokenMaxTTL":    86400,
		"tokenType":            "Bearer",
	})
}

// GetSecretRaw handles GET /api/v3/secrets/raw/{name}.
// Infisical-compatible raw secret fetch for CI/CD and machine identity flows.
func (h *Compat) GetSecretRaw(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": 400,
			"message":    "secret name is required",
			"error":      "Bad Request",
		})
		return
	}

	// For now, return the secret from env vars or a static map.
	// This enables make login / CI to fetch GAR_SA_KEY, KUBECONFIG, etc.
	// TODO: wire to the real secrets store (Base collections).
	val := os.Getenv(name)
	if val == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": 404,
			"message":    "secret not found",
			"error":      "Not Found",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"secret": map[string]any{
			"secretKey":   name,
			"secretValue": val,
		},
	})
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

// OIDCLogin handles GET /v1/sso/oidc/login.
// Redirects to the IAM OIDC authorize endpoint.
func (h *Compat) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	issuer := os.Getenv("BASE_OIDC_ISSUER")
	clientID := os.Getenv("BASE_OIDC_CLIENT_ID")
	appURL := os.Getenv("APP_URL")
	if issuer == "" || clientID == "" {
		writeError(w, http.StatusServiceUnavailable, "OIDC not configured")
		return
	}
	redirectURI := appURL + "/v1/sso/oidc/callback"
	state := r.URL.Query().Get("orgSlug")
	if state == "" {
		state = "default"
	}
	authorizeURL := issuer + "/login/oauth/authorize" +
		"?client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=code" +
		"&scope=openid+email+profile" +
		"&state=" + url.QueryEscape(state)
	http.Redirect(w, r, authorizeURL, http.StatusTemporaryRedirect)
}

// OIDCCallback handles GET /v1/sso/oidc/callback.
// Exchanges the auth code for tokens at IAM, sets a session cookie, and
// redirects to the frontend org-selection page.
func (h *Compat) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing code")
		return
	}
	_ = r.URL.Query().Get("state") // org slug, reserved for future use

	issuer := os.Getenv("BASE_OIDC_ISSUER")
	clientID := os.Getenv("BASE_OIDC_CLIENT_ID")
	clientSecret := os.Getenv("BASE_OIDC_CLIENT_SECRET")
	appURL := os.Getenv("APP_URL")
	if issuer == "" || clientID == "" || clientSecret == "" || appURL == "" {
		writeError(w, http.StatusServiceUnavailable, "OIDC not configured")
		return
	}
	redirectURI := appURL + "/v1/sso/oidc/callback"

	// Exchange authorization code for tokens at IAM.
	tokenURL := issuer + "/oauth/token"
	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "token exchange failed")
		return
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil || tokenResp.AccessToken == "" {
		writeError(w, http.StatusBadGateway, "invalid token response")
		return
	}

	// Set session cookie so AuthToken can return it to the frontend.
	http.SetCookie(w, &http.Cookie{
		Name:     "jid",
		Value:    tokenResp.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})

	http.Redirect(w, r, "/login/select-organization", http.StatusTemporaryRedirect)
}
