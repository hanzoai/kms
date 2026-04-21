// Command kmsd is the Hanzo KMS server — a thin wrapper around
// github.com/luxfi/kms with Hanzo-specific defaults.
//
// Implementation is identical to luxfi/kms (canonical). Only the defaults
// differ: Hanzo HTTP port (8443), ZAP port (9653), data directory
// (/data/hanzo-kms), branding (Hanzo), JWKS env var (HANZO_IAM_JWKS_URL).
//
// Wire format on the ZAP transport is the canonical luxfi/kms/pkg/zapserver
// surface: opcodes 0x0040 (Get) / 0x0041 (Put) / 0x0042 (List) / 0x0043
// (Delete). Hanzo and Lux clients interoperate.
//
// Configuration precedence: env vars > defaults.
//
//	Env vars:
//	  KMS_LISTEN                  - HTTP listen address (default ":8443" — Hanzo)
//	  KMS_ZAP_PORT                - ZAP listen port (default 9653 — Hanzo, 0 = disable)
//	  KMS_DATA_DIR                - ZapDB data directory (default "/data/hanzo-kms")
//	  KMS_NODE_ID                 - ZAP node ID (default "hanzo-kms-0")
//	  KMS_MASTER_KEY_B64          - 32-byte master key (base64) for ZAP secrets server
//	  KMS_ENCRYPTION_KEY_B64      - 32-byte ZapDB at-rest key
//	  HANZO_IAM_JWKS_URL          - Hanzo IAM JWKS endpoint (replaces IAM_JWKS_URL)
//	  HANZO_IAM_ENDPOINT          - Hanzo IAM endpoint (replaces IAM_ENDPOINT)
//	  HANZO_IAM_EXPECTED_ISSUER   - required iss claim (per-env, no cross-env trust)
//	  HANZO_IAM_EXPECTED_AUDIENCE - required aud claim (default "kms")
//	  HANZO_IAM_LEEWAY_SECONDS    - clock skew tolerance (0..5, default 0)
//	  KMS_AUTH_MODE               - "iam" (default, required in prod) or "none" (dev only)
//	  KMS_DEV_MODE                - "true" to allow KMS_AUTH_MODE=none
//	  IAM_ENDPOINT                - fallback if HANZO_IAM_ENDPOINT unset
//	  MPC_ADDR                    - ZAP address (host:port); empty = mDNS discovery
//	  MPC_VAULT_ID                - MPC vault ID (required for threshold signing)
//	  BRAND_NAME                  - Branding for startup banner (default "Hanzo")
//
//	S3 replication (ZapDB Replicator):
//	  REPLICATE_S3_ENDPOINT   - S3 endpoint (empty = replication disabled)
//	  REPLICATE_S3_BUCKET     - S3 bucket (default "hanzo-kms-backups")
//	  REPLICATE_S3_REGION     - S3 region (default "us-central1")
//	  REPLICATE_S3_ACCESS_KEY
//	  REPLICATE_S3_SECRET_KEY
//	  REPLICATE_AGE_RECIPIENT - age public key for backup encryption
//	  REPLICATE_PATH          - S3 key prefix (default "hanzo-kms/{KMS_NODE_ID}")
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	badger "github.com/luxfi/zapdb"

	"github.com/hanzoai/kms/pkg/auth"
	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/kms/pkg/zapserver"
	"github.com/luxfi/zap"
)

// Hanzo defaults (override luxfi/kms canonical defaults).
const (
	defaultListen   = ":8443"
	defaultZapPort  = "9653"
	defaultDataDir  = "/data/hanzo-kms"
	defaultNodeID   = "hanzo-kms-0"
	defaultBrand    = "Hanzo"
	defaultS3Bucket = "hanzo-kms-backups"
	defaultS3Path   = "hanzo-kms"
)

func main() {
	// --help support so operators can confirm Hanzo defaults.
	help := flag.Bool("help", false, "show help and exit")
	flag.BoolVar(help, "h", false, "show help and exit (shorthand)")
	flag.Usage = printUsage
	flag.Parse()
	if *help {
		printUsage()
		return
	}

	brand := envOr("BRAND_NAME", defaultBrand)
	mpcAddr := envOr("MPC_ADDR", "")
	vaultID := envOr("MPC_VAULT_ID", "")
	nodeID := envOr("KMS_NODE_ID", defaultNodeID)
	iamEndpoint := envOr("HANZO_IAM_ENDPOINT", envOr("IAM_ENDPOINT", "https://hanzo.id"))
	jwksURL := envOr("HANZO_IAM_JWKS_URL", envOr("IAM_JWKS_URL", ""))
	expectedIss := envOr("HANZO_IAM_EXPECTED_ISSUER", "")
	expectedAud := envOr("HANZO_IAM_EXPECTED_AUDIENCE", "kms")
	leewaySec, _ := strconv.Atoi(envOr("HANZO_IAM_LEEWAY_SECONDS", "0"))
	authMode := strings.ToLower(envOr("KMS_AUTH_MODE", "iam"))
	devMode := strings.EqualFold(envOr("KMS_DEV_MODE", ""), "true")
	dataDir := envOr("KMS_DATA_DIR", defaultDataDir)
	listen := envOr("KMS_LISTEN", defaultListen)

	log.Printf("%s KMS — thin wrapper over luxfi/kms (canonical)", brand)
	log.Printf("  listen=%s zap_port=%s data=%s node_id=%s",
		listen, envOr("KMS_ZAP_PORT", defaultZapPort), dataDir, nodeID)
	if jwksURL != "" {
		log.Printf("  iam.jwks=%s iss=%s aud=%s leeway=%ds",
			jwksURL, expectedIss, expectedAud, leewaySec)
	}

	// Build the JWT validator. Refuses to start without JWKS + iss + aud in
	// production — per-env trust boundary is mandatory. Dev can set
	// KMS_AUTH_MODE=none + KMS_DEV_MODE=true to bypass (local-only).
	validator := mustBuildValidator(authMode, devMode, jwksURL, expectedIss, expectedAud, leewaySec)

	// Open ZapDB at the Hanzo data dir.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("kmsd: create data dir %s: %v", dataDir, err)
	}
	dbOpts := badger.DefaultOptions(dataDir).
		WithLogger(zapdbLogger{}).
		WithEncryptionKey(masterKeyFromEnv()).
		WithIndexCacheSize(64 << 20)
	db, err := badger.Open(dbOpts)
	if err != nil {
		log.Fatalf("kmsd: open zapdb at %s: %v", dataDir, err)
	}
	defer db.Close()

	log.Printf("kmsd: zapdb opened at %s", dataDir)

	// S3 replication (defaults: hanzo-kms-backups bucket, hanzo-kms/<node> path).
	if rep := startReplicator(db, nodeID); rep != nil {
		defer rep.Stop()
	}

	mux := http.NewServeMux()

	// protect wraps a handler in the JWT validator (nil validator = pass-through
	// for dev mode). ALL sensitive routes go through this — secrets, keys,
	// status. /healthz and /v1/kms/auth/login are intentionally unauthenticated.
	protect := func(h http.HandlerFunc) http.Handler {
		if validator == nil {
			return h
		}
		return validator.Middleware(h)
	}

	// Health — unauthenticated on purpose (liveness probe).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "kms", "brand": brand})
	})

	// Machine identity auth via IAM (canonical luxfi/kms route).
	// This endpoint exchanges client_credentials for an access_token — it
	// MUST remain unauthenticated (you can't hold a token before you have it).
	mux.HandleFunc("POST /v1/kms/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ClientID     string `json:"clientId"`
			ClientSecret string `json:"clientSecret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" || req.ClientSecret == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"statusCode": 400, "message": "clientId and clientSecret required"})
			return
		}
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {req.ClientID},
			"client_secret": {req.ClientSecret},
		}
		resp, err := http.PostForm(iamEndpoint+"/api/login/oauth/access_token", form)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"statusCode": 502, "message": "identity provider unreachable"})
			return
		}
		defer resp.Body.Close()
		var tok map[string]any
		json.NewDecoder(resp.Body).Decode(&tok)
		at, _ := tok["access_token"].(string)
		if at == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"statusCode": 401, "message": "invalid credentials"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"accessToken": at, "expiresIn": 86400, "tokenType": "Bearer"})
	})

	// Secret store — canonical luxfi/kms surface. All routes below require
	// a valid per-env JWT (iss + aud + exp + kid pinned to this env's JWKS).
	secStore := store.NewSecretStore(db)

	mux.Handle("GET /v1/kms/orgs/{org}/secrets/{rest...}", protect(func(w http.ResponseWriter, r *http.Request) {
		rest := r.PathValue("rest")
		idx := strings.LastIndex(rest, "/")
		if idx < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "path and name required"})
			return
		}
		path, name := rest[:idx], rest[idx+1:]
		env := r.URL.Query().Get("env")
		if env == "" {
			env = "default"
		}
		sec, err := secStore.Get(path, name, env)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"secret": map[string]any{"value": string(sec.Ciphertext)},
		})
	}))

	mux.Handle("POST /v1/kms/orgs/{org}/secrets", protect(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Path  string `json:"path"`
			Name  string `json:"name"`
			Env   string `json:"env"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "name and value required"})
			return
		}
		if req.Env == "" {
			req.Env = "default"
		}
		sec := &store.Secret{
			Name:       req.Name,
			Path:       req.Path,
			Env:        req.Env,
			Ciphertext: []byte(req.Value),
		}
		if err := secStore.Put(sec); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"message": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
	}))

	mux.Handle("DELETE /v1/kms/orgs/{org}/secrets/{rest...}", protect(func(w http.ResponseWriter, r *http.Request) {
		rest := r.PathValue("rest")
		idx := strings.LastIndex(rest, "/")
		if idx < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "path and name required"})
			return
		}
		path, name := rest[:idx], rest[idx+1:]
		env := r.URL.Query().Get("env")
		if env == "" {
			env = "default"
		}
		if err := secStore.Delete(path, name, env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	// Legacy: env-backed secret fetch (canonical luxfi/kms route).
	mux.Handle("GET /v1/kms/secrets/{name}", protect(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "secret name required"})
			return
		}
		val := os.Getenv(name)
		if val == "" {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"secret": map[string]any{"secretKey": name, "secretValue": val},
		})
	}))

	// MPC key management — only when MPC_VAULT_ID is set.
	if vaultID != "" {
		zapClient, zerr := mpc.NewZapClient(nodeID, mpcAddr)
		if zerr != nil {
			log.Fatalf("kmsd: zap client: %v", zerr)
		}
		keyStore, kerr := store.New(db)
		if kerr != nil {
			log.Fatalf("kmsd: key store: %v", kerr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if status, err := zapClient.Status(ctx); err != nil {
			log.Printf("kmsd: WARNING: mpc unreachable via ZAP: %v", err)
		} else {
			log.Printf("kmsd: mpc ready=%v peers=%d/%d mode=%s",
				status.Ready, status.ConnectedPeers, status.ExpectedPeers, status.Mode)
		}
		cancel()

		mgr := keys.NewManager(zapClient, keyStore, vaultID)
		registerKMSKeyRoutes(mux, protect, mgr, zapClient)
	} else {
		log.Printf("kmsd: MPC_VAULT_ID not set — running in secrets-only mode (no threshold signing)")
	}

	// ZAP secrets server — canonical luxfi/kms/pkg/zapserver. Wire-compatible
	// with luxfi clients (opcodes 0x0040..0x0043).
	masterKeyB64 := envOr("KMS_MASTER_KEY_B64", "")
	zapPortStr := envOr("KMS_ZAP_PORT", defaultZapPort)
	zapPort, _ := strconv.Atoi(zapPortStr)
	if masterKeyB64 != "" && zapPort > 0 {
		masterKey, kerr := base64.StdEncoding.DecodeString(masterKeyB64)
		if kerr != nil || len(masterKey) != 32 {
			log.Printf("kmsd: KMS_MASTER_KEY_B64 invalid (need 32 bytes base64); ZAP secrets-server disabled")
		} else {
			n := zap.NewNode(zap.NodeConfig{
				NodeID:      nodeID + "-secrets",
				ServiceType: "_kms._tcp",
				Port:        zapPort,
			})
			if serr := n.Start(); serr != nil {
				log.Printf("kmsd: ZAP secrets-server failed to start on :%d: %v", zapPort, serr)
			} else {
				zs := zapserver.New(zapserver.Config{
					Store:     secStore,
					MasterKey: masterKey,
					Logger:    slog.Default(),
				})
				zs.Register(n)
				log.Printf("kmsd: ZAP secrets-server listening on :%d (service=_kms._tcp)", zapPort)
			}
		}
	} else {
		log.Printf("kmsd: ZAP secrets-server disabled (set KMS_MASTER_KEY_B64 and KMS_ZAP_PORT to enable)")
	}

	// Static frontend (Hanzo-branded UI dist) — served at root if present.
	frontendDir := envOr("KMS_FRONTEND_DIR", "/app/frontend")
	if info, ferr := os.Stat(frontendDir); ferr == nil && info.IsDir() {
		mux.Handle("/", http.FileServer(http.Dir(frontendDir)))
		log.Printf("kmsd: static frontend at %s", frontendDir)
	}

	// HTTP server.
	srv := &http.Server{
		Addr:         listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		log.Printf("kmsd: HTTP listening on %s", listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("kmsd: http: %v", err)
		}
	}()

	// Graceful shutdown.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("kmsd: shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func registerKMSKeyRoutes(mux *http.ServeMux, protect func(http.HandlerFunc) http.Handler, mgr *keys.Manager, mpcBackend keys.MPCBackend) {
	mux.Handle("POST /v1/kms/keys/generate", protect(func(w http.ResponseWriter, r *http.Request) {
		var req keys.GenerateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if req.ValidatorID == "" || req.Threshold < 2 || req.Parties < req.Threshold {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid keygen params"})
			return
		}
		ks, err := mgr.GenerateValidatorKeys(r.Context(), req)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, ks)
	}))

	mux.Handle("GET /v1/kms/keys", protect(func(w http.ResponseWriter, r *http.Request) {
		list := mgr.List()
		if list == nil {
			list = []*keys.ValidatorKeySet{}
		}
		writeJSON(w, http.StatusOK, list)
	}))

	mux.Handle("GET /v1/kms/keys/{id}", protect(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ks, err := mgr.Get(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, ks)
	}))

	mux.Handle("POST /v1/kms/keys/{id}/sign", protect(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var req keys.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Message) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message required"})
			return
		}
		var resp *keys.SignResponse
		var err error
		switch req.KeyType {
		case "bls":
			resp, err = mgr.SignWithBLS(r.Context(), id, req.Message)
		case "ringtail":
			resp, err = mgr.SignWithRingtail(r.Context(), id, req.Message)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key_type must be 'bls' or 'ringtail'"})
			return
		}
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}))

	mux.Handle("POST /v1/kms/keys/{id}/rotate", protect(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var req keys.RotateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		ks, err := mgr.Rotate(r.Context(), id, req)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ks)
	}))

	mux.Handle("GET /v1/kms/status", protect(func(w http.ResponseWriter, r *http.Request) {
		status, err := mpcBackend.Status(r.Context())
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]string{
				"kms": "ok", "mpc": "unreachable", "details": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"kms": "ok", "mpc": status})
	}))
}

func startReplicator(db *badger.DB, nodeID string) *badger.Replicator {
	endpoint := os.Getenv("REPLICATE_S3_ENDPOINT")
	if endpoint == "" {
		log.Printf("kmsd: S3 replication disabled (set REPLICATE_S3_ENDPOINT to enable)")
		return nil
	}
	cfg := badger.ReplicatorConfig{
		Endpoint:  endpoint,
		Bucket:    envOr("REPLICATE_S3_BUCKET", defaultS3Bucket),
		Region:    envOr("REPLICATE_S3_REGION", "us-central1"),
		AccessKey: os.Getenv("REPLICATE_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("REPLICATE_S3_SECRET_KEY"),
		UseSSL:    !strings.HasPrefix(endpoint, "http://"),
		Path:      envOr("REPLICATE_PATH", fmt.Sprintf("%s/%s", defaultS3Path, nodeID)),
		Interval:  time.Second,
	}
	rep, err := badger.NewReplicator(db, cfg)
	if err != nil {
		log.Printf("kmsd: WARNING: S3 replicator init failed: %v — replication disabled", err)
		return nil
	}
	go rep.Start(context.Background())
	log.Printf("kmsd: S3 replication → %s/%s/%s", endpoint, cfg.Bucket, cfg.Path)
	return rep
}

// mustBuildValidator constructs the JWT validator from env config.
//
// Production (KMS_AUTH_MODE=iam, default): JWKS + iss + aud are REQUIRED.
// Missing any → log.Fatalf. No fall-through to unauthenticated mode.
//
// Dev (KMS_AUTH_MODE=none + KMS_DEV_MODE=true): returns nil — caller
// treats nil as pass-through. The KMS_DEV_MODE guard exists so a stray
// KMS_AUTH_MODE=none in a prod env still refuses to start.
func mustBuildValidator(authMode string, devMode bool, jwksURL, expectedIss, expectedAud string, leewaySec int) *auth.Validator {
	if authMode == "none" {
		if !devMode {
			log.Fatalf("kmsd: KMS_AUTH_MODE=none requires KMS_DEV_MODE=true — refusing to start unauthenticated in prod")
		}
		log.Printf("kmsd: WARNING KMS_AUTH_MODE=none — unauthenticated (dev-only!)")
		return nil
	}
	if jwksURL == "" {
		log.Fatalf("kmsd: HANZO_IAM_JWKS_URL required (or set KMS_AUTH_MODE=none + KMS_DEV_MODE=true for local dev)")
	}
	if expectedIss == "" {
		log.Fatalf("kmsd: HANZO_IAM_EXPECTED_ISSUER required — per-env trust boundary is mandatory")
	}
	if expectedAud == "" {
		// Should never hit — defaulted to "kms" in main.
		log.Fatalf("kmsd: HANZO_IAM_EXPECTED_AUDIENCE required")
	}
	v, err := auth.NewValidator(auth.Config{
		JWKSURL:          jwksURL,
		ExpectedIssuer:   expectedIss,
		ExpectedAudience: expectedAud,
		Leeway:           time.Duration(leewaySec) * time.Second,
	})
	if err != nil {
		log.Fatalf("kmsd: JWT validator init: %v", err)
	}
	log.Printf("kmsd: JWT validator armed (iss=%s aud=%s leeway=%ds)", expectedIss, expectedAud, leewaySec)
	return v
}

func masterKeyFromEnv() []byte {
	b64 := os.Getenv("KMS_ENCRYPTION_KEY_B64")
	if b64 == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) != 32 {
		log.Printf("kmsd: KMS_ENCRYPTION_KEY_B64 invalid (need 32 bytes base64); at-rest encryption disabled")
		return nil
	}
	return key
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type zapdbLogger struct{}

func (zapdbLogger) Errorf(format string, args ...interface{}) {
	slog.Error(fmt.Sprintf(format, args...))
}
func (zapdbLogger) Warningf(format string, args ...interface{}) {
	slog.Warn(fmt.Sprintf(format, args...))
}
func (zapdbLogger) Infof(format string, args ...interface{}) {
	slog.Info(fmt.Sprintf(format, args...))
}
func (zapdbLogger) Debugf(format string, args ...interface{}) {
	slog.Debug(fmt.Sprintf(format, args...))
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Hanzo KMS — thin wrapper over luxfi/kms (canonical implementation)

Usage:
  kmsd [--help]

Defaults (Hanzo-specific overrides of luxfi/kms):
  HTTP listen        : %s   (luxfi default :8080)
  ZAP listen port    : %s   (luxfi default 9652)
  Data directory     : %s    (luxfi default /data/kms)
  Node ID            : %s   (luxfi default kms-0)
  Branding           : %s   (BRAND_NAME env)
  IAM JWKS env var   : HANZO_IAM_JWKS_URL  (falls back to IAM_JWKS_URL)
  IAM endpoint env   : HANZO_IAM_ENDPOINT  (falls back to IAM_ENDPOINT)
  S3 backups bucket  : %s
  S3 backups prefix  : %s/<node_id>

Wire-format compatibility:
  ZAP opcodes 0x0040..0x0043 (canonical luxfi/kms/pkg/zapserver) — Hanzo and
  Lux KMS clients interoperate over the binary transport.

See: https://github.com/luxfi/kms (canonical implementation).
`,
		defaultListen, defaultZapPort, defaultDataDir, defaultNodeID, defaultBrand,
		defaultS3Bucket, defaultS3Path,
	)
}
