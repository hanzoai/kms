// Package server provides the HTTP server setup for kmsd.
package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/handler"
	"github.com/hanzoai/kms/internal/mpc"
	"github.com/hanzoai/kms/internal/store"
	"github.com/hanzoai/kms/internal/transit"

	"github.com/hanzoai/base/core"
)

// Config holds all dependencies for the server.
type Config struct {
	App      core.App
	MPC      *mpc.ZapClient
	JWKS     *auth.JWKSValidator
	VaultID  string
	AuthMode string // "iam" or "none"
}

// NewRouter creates and configures the chi router with all KMS routes.
func NewRouter(cfg Config) *chi.Mux {
	secretStore := store.NewSecretStore(cfg.App)
	serviceSecretStore := store.NewServiceSecretStore(cfg.App)
	keyStore := store.NewKeyStore(cfg.App)
	memberStore := store.NewMemberStore(cfg.App)
	auditStore := store.NewAuditStore(cfg.App)
	transitKeyStore := store.NewTransitKeyStore(cfg.App)
	tenantStore := store.NewTenantStore(cfg.App)
	tenantConfigStore := store.NewTenantConfigStore(cfg.App)
	integrationStore := store.NewIntegrationStore(cfg.App)
	idempotencyStore := store.NewIdempotencyStore(cfg.App)

	transitEngine := transit.NewEngine(transitKeyStore)

	secretsH := handler.NewSecrets(secretStore)
	keysH := handler.NewKeys(keyStore, cfg.MPC, cfg.VaultID)
	membersH := handler.NewMembers(memberStore)
	complianceH := handler.NewCompliance(auditStore)
	transitH := handler.NewTransit(transitEngine)
	statusH := handler.NewStatus(cfg.MPC)
	compatH := handler.NewCompat()
	tenantsH := handler.NewTenants(tenantStore, auditStore)
	tenantConfigH := handler.NewTenantConfig(tenantConfigStore, auditStore)
	tenantSecretsH := handler.NewTenantSecrets(serviceSecretStore, auditStore)
	integrationsH := handler.NewIntegrations(integrationStore, auditStore)
	secretsByIDH := handler.NewSecretsByID(serviceSecretStore, auditStore, idempotencyStore)

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	RegisterRoutes(
		r, cfg.JWKS, cfg.AuthMode,
		secretsH, keysH, membersH, complianceH,
		transitH, statusH, compatH,
		tenantsH, tenantConfigH, tenantSecretsH, integrationsH, secretsByIDH,
	)

	return r
}
