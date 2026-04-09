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
	r.Get("/v1/admin/config", status.ServerConfig)
	r.Get("/v1/status", compat.StatusEnhanced)
	r.Post("/v1/auth/login1", compat.SRPLogin1)
	r.Post("/v1/auth/login2", compat.SRPLogin2)

	// Auth token check — must NOT 401 for unauthenticated users.
	// The frontend calls this to check for existing sessions.
	// Returns 200 with empty token when no valid session.
	r.Post("/v1/auth/token", compat.AuthToken)
	r.Post("/v1/auth/select-organization", compat.SelectOrg)

	// Authenticated routes.
	r.Group(func(r chi.Router) {
		if authMode == "iam" && jwks != nil {
			r.Use(auth.Middleware(jwks))
		}

		r.Get("/v1/kms/status", status.StatusCheck)

		// User + org endpoints.
		r.Get("/v1/user", compat.GetUser)
		r.Get("/v1/user/duplicate-accounts", compat.DuplicateAccounts)
		r.Get("/v1/organization", compat.ListOrgs)
		r.Get("/v1/organization/{orgId}", compat.GetOrg)
		r.Get("/v1/organization/{orgId}/subscription", compat.OrgSubscription)
		r.Get("/v1/organization/{orgId}/permissions", compat.OrgPermissions)
		r.Get("/v1/sub-organizations", compat.SubOrganizations)

		// ZK Secrets.
		r.Post("/v1/orgs/{org}/zk/secrets", secrets.Create)
		r.Get("/v1/orgs/{org}/zk/secrets", secrets.List)
		r.Get("/v1/orgs/{org}/zk/secrets/{path}/{name}", secrets.Get)
		r.Delete("/v1/orgs/{org}/zk/secrets/{path}/{name}", secrets.Delete)

		// Validator keys.
		r.Post("/v1/keys/generate", keys.Generate)
		r.Get("/v1/keys", keys.List)
		r.Get("/v1/keys/{id}", keys.Get)
		r.Post("/v1/keys/{id}/sign", keys.Sign)
		r.Post("/v1/keys/{id}/rotate", keys.Rotate)

		// Members.
		r.Post("/v1/orgs/{org}/members", members.Create)
		r.Get("/v1/orgs/{org}/members", members.List)
		r.Delete("/v1/orgs/{org}/members/{memberID}", members.Delete)

		// Audit.
		r.Get("/v1/orgs/{org}/audit", compliance.AuditLog)

		// Transit engine.
		r.Post("/v1/transit/keys", transit.CreateKey)
		r.Post("/v1/transit/encrypt/{name}", transit.Encrypt)
		r.Post("/v1/transit/decrypt/{name}", transit.Decrypt)
		r.Post("/v1/transit/sign/{name}", transit.Sign)
		r.Post("/v1/transit/verify/{name}", transit.Verify)
	})
}
