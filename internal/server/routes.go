package server

import (
	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/handler"
)

// RegisterRoutes wires all handlers onto the chi router.
func RegisterRoutes(
	r *chi.Mux,
	jwks *auth.JWKSValidator,
	authMode string,
	secrets *handler.Secrets,
	keys *handler.Keys,
	members *handler.Members,
	compliance *handler.Compliance,
	transit *handler.Transit,
	status *handler.Status,
	compat *handler.Compat,
) {
	// Unauthenticated — frontend boot + auth flow.
	r.Get("/healthz", status.Healthz)
	r.Get("/v1/kms/admin/config", status.ServerConfig)
	r.Get("/v1/kms/status", compat.StatusEnhanced)
	r.Post("/v1/kms/auth/login1", compat.SRPLogin1)
	r.Post("/v1/kms/auth/login2", compat.SRPLogin2)

	// Machine identity auth (CI/CD, make login, SDKs).
	// v2/v4 = canonical KMS paths. v1/v3 = legacy Infisical compat.
	r.Post("/v1/kms/auth/login", compat.UniversalAuthLogin)
	r.Get("/v1/kms/secrets/{name}", compat.GetSecretRaw)

	// Auth token check — must NOT 401 for unauthenticated users.
	// The frontend calls this to check for existing sessions.
	// Returns 200 with empty token when no valid session.
	r.Post("/v1/kms/auth/token", compat.AuthToken)
	r.Post("/v1/kms/auth/select-organization", compat.SelectOrg)
	r.Get("/v1/kms/sso/oidc/login", compat.OIDCLogin)
	r.Get("/v1/kms/sso/oidc/callback", compat.OIDCCallback)

	// Authenticated routes.
	r.Group(func(r chi.Router) {
		if authMode == "iam" && jwks != nil {
			r.Use(auth.Middleware(jwks))
		}

		r.Get("/v1/kms/status", status.StatusCheck)

		// User + org endpoints.
		r.Get("/v1/kms/user", compat.GetUser)
		r.Get("/v1/kms/user/duplicate-accounts", compat.DuplicateAccounts)
		r.Get("/v1/kms/organization", compat.ListOrgs)
		r.Get("/v1/kms/organization/{orgId}", compat.GetOrg)
		r.Get("/v1/kms/organization/{orgId}/subscription", compat.OrgSubscription)
		r.Get("/v1/kms/organization/{orgId}/permissions", compat.OrgPermissions)
		r.Get("/v1/kms/sub-organizations", compat.SubOrganizations)

		// ZK Secrets.
		r.Post("/v1/kms/orgs/{org}/zk/secrets", secrets.Create)
		r.Get("/v1/kms/orgs/{org}/zk/secrets", secrets.List)
		r.Get("/v1/kms/orgs/{org}/zk/secrets/{path}/{name}", secrets.Get)
		r.Delete("/v1/kms/orgs/{org}/zk/secrets/{path}/{name}", secrets.Delete)

		// Validator keys.
		r.Post("/v1/kms/keys/generate", keys.Generate)
		r.Get("/v1/kms/keys", keys.List)
		r.Get("/v1/kms/keys/{id}", keys.Get)
		r.Post("/v1/kms/keys/{id}/sign", keys.Sign)
		r.Post("/v1/kms/keys/{id}/rotate", keys.Rotate)

		// Members.
		r.Post("/v1/kms/orgs/{org}/members", members.Create)
		r.Get("/v1/kms/orgs/{org}/members", members.List)
		r.Delete("/v1/kms/orgs/{org}/members/{memberID}", members.Delete)

		// Audit.
		r.Get("/v1/kms/orgs/{org}/audit", compliance.AuditLog)

		// Transit engine.
		r.Post("/v1/kms/transit/keys", transit.CreateKey)
		r.Post("/v1/kms/transit/encrypt/{name}", transit.Encrypt)
		r.Post("/v1/kms/transit/decrypt/{name}", transit.Decrypt)
		r.Post("/v1/kms/transit/sign/{name}", transit.Sign)
		r.Post("/v1/kms/transit/verify/{name}", transit.Verify)
	})
}
