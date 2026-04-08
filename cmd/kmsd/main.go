// Command kmsd starts the KMS server on Base.
//
// Configuration (env vars):
//
//	MPC_ADDR       - ZAP address (host:port); empty = mDNS discovery (dev only)
//	MPC_VAULT_ID   - MPC vault ID for validator keys (required)
//	KMS_NODE_ID    - ZAP node ID (default "kms-0")
//	IAM_JWKS_URL   - JWKS endpoint for JWT validation (required when IAM auth enabled)
//	KMS_AUTH_MODE  - "iam" (default, requires IAM_JWKS_URL) or "none" (dev only)
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
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

	if vaultID == "" {
		log.Fatal("kmsd: MPC_VAULT_ID is required")
	}

	zapClient, err := mpc.NewZapClient(nodeID, mpcAddr)
	if err != nil {
		log.Fatalf("kmsd: zap client: %v", err)
	}
	defer zapClient.Close()

	app := base.New()

	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		// Bootstrap all KMS collections.
		if err := store.Bootstrap(e.App); err != nil {
			return err
		}

		// Verify MPC reachability.
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if status, err := zapClient.Status(checkCtx); err != nil {
			log.Printf("kmsd: WARNING: mpc unreachable via ZAP: %v", err)
		} else {
			log.Printf("kmsd: mpc ready=%v peers=%d/%d mode=%s",
				status.Ready, status.ConnectedPeers, status.ExpectedPeers, status.Mode)
		}
		checkCancel()

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

		// Mount the chi router onto the Base router.
		e.Router.GET("/healthz", func(re *core.RequestEvent) error {
			chiRouter.ServeHTTP(re.Response, re.Request)
			return nil
		})

		// Mount all /v1/* routes through chi.
		e.Router.Any("/v1/{path...}", func(re *core.RequestEvent) error {
			chiRouter.ServeHTTP(re.Response, re.Request)
			return nil
		})

		// Redirect root to healthz.
		e.Router.GET("/", func(re *core.RequestEvent) error {
			http.Redirect(re.Response, re.Request, "/healthz", http.StatusTemporaryRedirect)
			return nil
		})

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
