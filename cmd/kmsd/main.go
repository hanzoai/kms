// Command kmsd starts the KMS server on Base.
//
// Serves the secrets management UI at / and the Base admin at /_/.
//
// Configuration (env vars):
//
//	MPC_ADDR          - ZAP address (host:port); empty = mDNS discovery (dev only)
//	MPC_VAULT_ID      - MPC vault ID for validator keys (optional)
//	KMS_NODE_ID       - ZAP node ID (default "kms-0")
//	IAM_JWKS_URL      - JWKS endpoint for JWT validation (required when KMS_AUTH_MODE=iam)
//	KMS_AUTH_MODE     - "iam" (default) or "none" (dev only)
//	APP_NAME          - Display name in UI (default "KMS")
//	APP_URL           - Public URL (optional)
//	LOGO_URL          - Logo URL (optional, blank = no logo)
//	KMS_FRONTEND_DIR  - Path to secrets UI dist (default /app/frontend)
//	DISABLE_ADMIN_UI  - Set to "true" to disable Base admin at /_/
package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/plugins/replicate"

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
	devMode := envOr("KMS_DEV_MODE", "") == "true"

	// F2: Refuse to start without auth unless KMS_DEV_MODE=true.
	if authMode != "iam" && !devMode {
		log.Fatal("kmsd: KMS_AUTH_MODE must be 'iam' in production. Set KMS_DEV_MODE=true for insecure dev mode.")
	}
	frontendDir := envOr("KMS_FRONTEND_DIR", "/app/frontend")
	disableAdmin := envOr("DISABLE_ADMIN_UI", "") == "true"

	var zapClient *mpc.ZapClient
	if vaultID != "" {
		var err error
		zapClient, err = mpc.NewZapClient(nodeID, mpcAddr)
		if err != nil {
			log.Fatalf("kmsd: zap client: %v", err)
		}
		defer zapClient.Close()
	} else {
		log.Printf("kmsd: running without MPC backend (secrets-only mode)")
	}

	app := base.New()

	// In-process WAL replication to S3 — no sidecar needed.
	// No-op if REPLICATE_S3_ENDPOINT is not set.
	replicate.MustRegister(app)

	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		// H-3: Suppress installer token URL from stdout.
		// KMS uses IAM for auth — the Base installer flow is never needed.
		// Without this, every restart with an ephemeral DB prints a 30-min
		// privilege-escalation JWT to pod logs.
		e.InstallerFunc = nil

		// Branding from env — no hardcoded brand.
		s := e.App.Settings()
		s.Meta.AppName = envOr("APP_NAME", "KMS")
		s.Meta.AppURL = envOr("APP_URL", "")
		s.Meta.LogoURL = envOr("LOGO_URL", "")
		s.Meta.HideControls = envOr("HIDE_ADMIN_CONTROLS", "") == "true"
		if err := e.App.Save(s); err != nil {
			log.Printf("kmsd: WARNING: could not save settings: %v", err)
		}

		// Bootstrap KMS collections.
		if err := store.Bootstrap(e.App); err != nil {
			return err
		}

		// Check MPC if configured.
		if zapClient != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if st, err := zapClient.Status(ctx); err != nil {
				log.Printf("kmsd: WARNING: mpc unreachable: %v", err)
			} else {
				log.Printf("kmsd: mpc ready=%v peers=%d/%d mode=%s",
					st.Ready, st.ConnectedPeers, st.ExpectedPeers, st.Mode)
			}
			cancel()
		}

		// Auth.
		var jwks *auth.JWKSValidator
		if authMode == "iam" {
			if jwksURL == "" {
				return fmt.Errorf("kmsd: IAM_JWKS_URL required when KMS_AUTH_MODE=iam")
			}
			jwks = auth.NewJWKSValidator(jwksURL)
		} else {
			log.Printf("kmsd: WARNING: auth disabled — dev only")
		}

		// API routes via chi.
		chiRouter := server.NewRouter(server.Config{
			App:      e.App,
			MPC:      zapClient,
			JWKS:     jwks,
			VaultID:  vaultID,
			AuthMode: authMode,
		})

		// Single catch-all: try chi first (KMS API), fall back to static.
		var frontendFS fs.FS
		if info, err := os.Stat(frontendDir); err == nil && info.IsDir() {
			frontendFS = os.DirFS(frontendDir)
			if disableAdmin {
				log.Printf("kmsd: secrets UI at /, admin disabled")
			} else {
				log.Printf("kmsd: secrets UI at /, admin at /_/")
			}
		}

		e.Router.Any("/{path...}", func(re *core.RequestEvent) error {
			path := re.Request.URL.Path

			// Block /_/ admin if disabled.
			if disableAdmin && strings.HasPrefix(path, "/_/") {
				re.Response.WriteHeader(404)
				return nil
			}

			// KMS API routes — delegate to chi (bypasses Base auth).
			if strings.HasPrefix(path, "/v1/kms/") || path == "/healthz" {
				chiRouter.ServeHTTP(re.Response, re.Request)
				return nil
			}

			// Static frontend.
			if frontendFS != nil {
				p := strings.TrimPrefix(path, "/")
				if p == "" {
					p = "index.html"
				}
				if err := re.FileFS(frontendFS, p); err == nil {
					return nil
				}
				return re.FileFS(frontendFS, "index.html")
			}

			return re.Next()
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
