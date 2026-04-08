// Command kmsd starts the KMS server on Base.
//
// Configuration (env vars):
//
//	MPC_ADDR       - ZAP address (host:port); empty = mDNS discovery (dev only)
//	MPC_VAULT_ID   - MPC vault ID for validator keys (required)
//	KMS_NODE_ID    - ZAP node ID (default "kms-0")
//	IAM_JWKS_URL   - JWKS endpoint for JWT validation (required when IAM auth enabled)
//	KMS_AUTH_MODE  - "iam" (default, requires IAM_JWKS_URL) or "none" (dev only)
//	APP_NAME         - Display name in admin UI (default "KMS")
//	APP_URL          - Public URL for admin UI links (optional)
//	LOGO_URL         - Logo URL for admin UI (optional, no default — blank = no logo)
//	KMS_FRONTEND_DIR - Path to Infisical React frontend dist (optional; serves at /)
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/mpc"
	"github.com/hanzoai/kms/internal/server"
	"github.com/hanzoai/kms/internal/store"
)

func main() {
	mpcAddr := envOr("MPC_ADDR", "")
	vaultID := envOr("MPC_VAULT_ID", "")
	nodeID := envOr("KMS_NODE_ID", "kms-0")
	jwksURL := envOr("IAM_JWKS_URL", "")
	authMode := envOr("KMS_AUTH_MODE", "iam")
	frontendDir := envOr("KMS_FRONTEND_DIR", "")

	var zapClient *mpc.ZapClient
	if vaultID != "" {
		var err error
		zapClient, err = mpc.NewZapClient(nodeID, mpcAddr)
		if err != nil {
			log.Fatalf("kmsd: zap client: %v", err)
		}
		defer zapClient.Close()
	} else {
		log.Printf("kmsd: MPC_VAULT_ID not set — running without MPC backend (secrets-only mode)")
	}

	app := base.New()

	// Apply branding from env — no hardcoded brand.
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		s := e.App.Settings()
		s.Meta.AppName = envOr("APP_NAME", "KMS")
		s.Meta.AppURL = envOr("APP_URL", "")
		s.Meta.LogoURL = envOr("LOGO_URL", "")
		s.Meta.HideControls = envOr("HIDE_ADMIN_CONTROLS", "") == "true"
		if err := e.App.Save(s); err != nil {
			log.Printf("kmsd: WARNING: could not save settings: %v", err)
		}

		// Bootstrap all KMS collections.
		if err := store.Bootstrap(e.App); err != nil {
			return err
		}

		// Verify MPC reachability (only if MPC backend is configured).
		if zapClient != nil {
			checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
			if mpcStatus, err := zapClient.Status(checkCtx); err != nil {
				log.Printf("kmsd: WARNING: mpc unreachable via ZAP: %v", err)
			} else {
				log.Printf("kmsd: mpc ready=%v peers=%d/%d mode=%s",
					mpcStatus.Ready, mpcStatus.ConnectedPeers, mpcStatus.ExpectedPeers, mpcStatus.Mode)
			}
			checkCancel()
		}

		// Initialize auth.
		var jwks *auth.JWKSValidator
		if authMode == "iam" {
			if jwksURL == "" {
				return fmt.Errorf("kmsd: IAM_JWKS_URL is required when KMS_AUTH_MODE=iam")
			}
			jwks = auth.NewJWKSValidator(jwksURL)
		} else {
			log.Printf("kmsd: WARNING: auth disabled (KMS_AUTH_MODE=%s) -- dev only", authMode)
		}

		// Build chi router with all handlers.
		chiRouter := server.NewRouter(server.Config{
			App:      e.App,
			MPC:      zapClient,
			JWKS:     jwks,
			VaultID:  vaultID,
			AuthMode: authMode,
		})

		// Mount chi router for /healthz and /v1/* on the Base router.
		chiHandler := func(re *core.RequestEvent) error {
			chiRouter.ServeHTTP(re.Response, re.Request)
			return nil
		}

		e.Router.GET("/healthz", chiHandler)
		e.Router.GET("/v1/{path...}", chiHandler)
		e.Router.POST("/v1/{path...}", chiHandler)
		e.Router.PUT("/v1/{path...}", chiHandler)
		e.Router.PATCH("/v1/{path...}", chiHandler)
		e.Router.DELETE("/v1/{path...}", chiHandler)

		// Serve Infisical React frontend at / if KMS_FRONTEND_DIR is set.
		// Base admin UI at /_/ and API routes at /v1/* take priority.
		if frontendDir != "" {
			frontendFS := os.DirFS(frontendDir)
			e.Router.GET("/{path...}", func(re *core.RequestEvent) error {
				p := strings.TrimPrefix(re.Request.URL.Path, "/")
				if p == "" {
					p = "index.html"
				}
				// Try serving the exact file.
				err := re.FileFS(frontendFS, p)
				if err == nil {
					return nil
				}
				// SPA fallback: serve index.html for paths that don't match a static file.
				if fallbackErr := re.FileFS(frontendFS, "index.html"); fallbackErr != nil {
					return err // return original error if index.html also missing
				}
				return nil
			})
			log.Printf("kmsd: serving frontend from %s at /", frontendDir)
		}

		return e.Next()
	})

	if err := app.Start(); err != nil {
		log.Fatalf("kmsd: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
