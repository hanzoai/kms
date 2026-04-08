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
) {
	// Unauthenticated.
	r.Get("/healthz", status.Healthz)

	// Infisical-compatible endpoints (frontend expects /api/v1/*).
	r.Get("/api/v1/admin/config", status.ServerConfig)

	// Authenticated routes.
	r.Group(func(r chi.Router) {
		if authMode == "iam" && jwks != nil {
			r.Use(auth.Middleware(jwks))
		}

		// Status.
		r.Get("/v1/status", status.StatusCheck)

		// ZK Secrets (per-org).
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

		// Members (per-org).
		r.Post("/v1/orgs/{org}/members", members.Create)
		r.Get("/v1/orgs/{org}/members", members.List)
		r.Delete("/v1/orgs/{org}/members/{memberID}", members.Delete)

		// Audit (per-org).
		r.Get("/v1/orgs/{org}/audit", compliance.AuditLog)

		// Transit engine.
		r.Post("/v1/transit/keys", transit.CreateKey)
		r.Post("/v1/transit/encrypt/{name}", transit.Encrypt)
		r.Post("/v1/transit/decrypt/{name}", transit.Decrypt)
		r.Post("/v1/transit/sign/{name}", transit.Sign)
		r.Post("/v1/transit/verify/{name}", transit.Verify)
	})
}
