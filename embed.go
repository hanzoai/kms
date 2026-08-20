// Package kms is the in-process Hanzo KMS server. It is a thin wrapper
// over github.com/luxfi/kms with Hanzo-specific defaults (port 8443,
// /data/hanzo-kms), explicit IAM/JWKS/issuer/audience config (no
// defaults — refuses to boot if missing), JWT verification (RFC 7519,
// no HS*, no alg=none), and identity-header hygiene.
//
// Secrets are stored in ZapDB at cfg.DataDir with optional at-rest
// encryption via KMS_ENCRYPTION_KEY_B64, and the in-process Replicator
// streams encrypted backups to S3. They are reached over the ZAP
// transport, whose authorizer is a signed consensus-authority snapshot
// (consensus.go) and which is disabled unless that snapshot is present.
//
// There is no HTTP secret plane here. Secret reads and writes over HTTP
// are served by cloud (apps/kms) on /v1/kms/orgs/{org}/secrets, which
// folds the caller's org into the storage key so one tenant's path
// cannot name another's record. This package therefore makes no
// authorization decision at all: IAM owns identity and permissions, and
// verifyJWT answers only "who signed this token".
//
// The HTTP surface is health, the IAM client-credentials login proxy,
// and the dashboard SPA. embed.go owns that route assembly plus the
// transport wiring, and exposes Embed(ctx, cfg) (*Embedded, error).
package kms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	badger "github.com/luxfi/zapdb"

	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/kms/pkg/zapserver"
	"github.com/luxfi/log"
	"github.com/luxfi/zap"
)

// Version is overridden at build time via -ldflags "-X
// github.com/hanzoai/kms.Version=...".
var Version = "dev"

// maxBodyBytes caps every POST body to prevent OOM via slowloris-style upload.
const maxBodyBytes = 1 << 20 // 1 MiB

// EmbedConfig configures the in-process Hanzo KMS server.
//
// Process-shape fields (DataDir, HTTPAddr, ZAPPort) resolve to the
// canonical defaults of the kmsd container image. Identity-coupled
// fields (IAMEndpoint, JWKSURL, ExpectedIssuer, ExpectedAudience) have
// no defaults — supply them via env or config or Embed refuses to
// boot.
type EmbedConfig struct {
	// DataDir is the ZapDB persistence root.
	// Empty → "/data/hanzo-kms" (production default).
	DataDir string

	// HTTPAddr is the bind address for the HTTP server.
	// Empty → ":8443". Use ":0" for an ephemeral port (tests).
	HTTPAddr string

	// IAMEndpoint is the Hanzo IAM origin used for the
	// /v1/kms/auth/login client_credentials proxy. Required.
	IAMEndpoint string

	// JWKSURL is the JWKS endpoint for verifying inbound JWTs.
	// Required when JWTKeySource is empty. Tests can point this at an
	// httptest.Server.
	JWKSURL string

	// JWTKeySource is an alias kept for parity with iam.EmbedConfig
	// and the fused-binary call site. When non-empty, overrides
	// JWKSURL. Empty → JWKSURL or default.
	JWTKeySource string

	// ZAPPort is the ZAP secrets-server listen port.
	// 0 → 9999. Negative disables.
	ZAPPort int

	// NodeID identifies this KMS instance for replication paths and
	// ZAP service discovery. Empty → "hanzo-kms-0".
	NodeID string

	// Env names the deployment environment. All envs (including dev)
	// must supply IAM_ISSUER, IAM_AUDIENCE, IAM_KEYS_URL or boot fails.
	// Empty → "dev".
	Env string

	// ExpectedIssuer is the iss claim a JWT must carry. Empty →
	// $IAM_ISSUER.
	ExpectedIssuer string

	// ExpectedAudience is the aud claim a JWT must carry (comma list
	// allowed). Empty → $IAM_AUDIENCE.
	ExpectedAudience string

	// SkipListen, when true, runs the bootstrap and registers all
	// routes/ZAP handlers, but does NOT bind the HTTP listener.
	// The parent serves the returned HTTPHandler() over its own
	// listener. Tests use this flag.
	SkipListen bool
}

// Embedded is the handle to a running Hanzo KMS server.
type Embedded struct {
	cfg EmbedConfig

	mux        *http.ServeMux
	handler    http.Handler // mux wrapped in stripIdentityHeaders + methodAllowlist
	httpServer *http.Server // nil when SkipListen=true

	db         *badger.DB
	replicator *badger.Replicator
	zapNode    *zap.Node // nil when ZAP server disabled
}

// Embed boots the Hanzo KMS server in-process and returns a handle.
//
// Embed is safe to call exactly once per process: it registers
// process-global JWT verification config. The fused hanzo binary calls
// Embed once at startup and keeps the handle for the lifetime of the
// process.
//
// The provided ctx is used for cancellation; if ctx is cancelled before
// Stop is called, Embed shuts the server down automatically.
func Embed(ctx context.Context, cfg EmbedConfig) (*Embedded, error) {
	cfg = applyEmbedDefaults(cfg)

	// Identity-coupled config — IAMEndpoint, ExpectedIssuer,
	// ExpectedAudience, JWKSURL — has no defaults. Refuses to boot if
	// missing, so a misconfig fails on the laptop instead of silently
	// rejecting tokens at staging (the hanzo.id default outage of
	// 2026-05-07).
	if err := validateProdConfigAtBoot(cfg); err != nil {
		return nil, fmt.Errorf("kms.Embed: %w", err)
	}

	// JWT verification contract. Boot refuses missing envs in prod.
	auth := authCfgValues{
		issuer:   cfg.ExpectedIssuer,
		audience: cfg.ExpectedAudience,
		jwksURL:  cfg.JWTKeySource,
	}
	if auth.jwksURL == "" {
		auth.jwksURL = cfg.JWKSURL
	}
	if err := validateAuthConfigAtBoot(cfg.Env, auth.issuer, auth.audience, auth.jwksURL); err != nil {
		return nil, fmt.Errorf("kms.Embed: auth config: %w", err)
	}
	applyAuthConfig(auth)
	log.Info("kms.Embed: auth configured",
		"iss", auth.issuer,
		"aud", auth.audience,
		"jwks", auth.jwksURL,
		"env", cfg.Env)

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("kms.Embed: create data dir %s: %w", cfg.DataDir, err)
	}

	dbOpts := badger.DefaultOptions(cfg.DataDir).
		WithLogger(zapdbLogger{}).
		WithEncryptionKey(masterKeyFromEnv()).
		WithIndexCacheSize(64 << 20)
	db, err := badger.Open(dbOpts)
	if err != nil {
		return nil, fmt.Errorf("kms.Embed: open zapdb at %s: %w", cfg.DataDir, err)
	}
	log.Info("kms.Embed: zapdb opened", "dir", cfg.DataDir, "version", Version)

	em := &Embedded{cfg: cfg, db: db}

	em.replicator = startReplicator(db, cfg.NodeID)

	secStore := store.NewSecretStore(db)

	mux := http.NewServeMux()
	registerHealth(mux)
	registerAuth(mux, cfg.IAMEndpoint)

	// Frontend SPA. The Dockerfile builds frontend/ → /app/frontend and
	// sets KMS_FRONTEND_DIR. When the env var resolves to a directory
	// containing index.html, register a catch-all handler at "/" that
	// serves static assets directly and falls back to index.html for
	// SPA client-side routes (/login, /dashboard, etc.). Anything that
	// hits an API path (/healthz, /v1/kms/**) takes the more-specific
	// route registered above; the SPA only fires on the catch-all.
	registerFrontend(mux)

	em.mux = mux
	em.handler = methodAllowlist(stripIdentityHeaders(mux))

	if zapNode := startZAPSecretServer(secStore, cfg); zapNode != nil {
		em.zapNode = zapNode
	}

	if !cfg.SkipListen {
		em.httpServer = &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           em.handler,
			ReadTimeout:       30 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			log.Info("kms.Embed: HTTP listening", "addr", cfg.HTTPAddr)
			if err := em.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Crit("kms.Embed: http", "err", err)
			}
		}()
	}

	go func() {
		<-ctx.Done()
		_ = em.Stop(context.Background())
	}()

	return em, nil
}

// HTTPHandler returns the wrapped HTTP handler (mux + header hygiene +
// method allowlist). Mount this behind a parent listener (e.g. a fused
// hanzo binary or hanzoai/gateway).
func (e *Embedded) HTTPHandler() http.Handler {
	if e == nil {
		return http.NotFoundHandler()
	}
	return e.handler
}

// ZAPPort returns the ZAP secrets-server port (0 when disabled).
func (e *Embedded) ZAPPort() int {
	if e == nil || e.zapNode == nil {
		return 0
	}
	return e.cfg.ZAPPort
}

// Stop gracefully shuts down the KMS server. Idempotent.
func (e *Embedded) Stop(ctx context.Context) error {
	if e == nil {
		return nil
	}
	if e.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_ = e.httpServer.Shutdown(shutdownCtx)
		e.httpServer = nil
	}
	if e.zapNode != nil {
		e.zapNode.Stop()
		e.zapNode = nil
	}
	if e.replicator != nil {
		e.replicator.Stop()
		e.replicator = nil
	}
	if e.db != nil {
		_ = e.db.Close()
		e.db = nil
	}
	log.Info("kms.Embed: stopped")
	return nil
}

// applyEmbedDefaults resolves process-shape EmbedConfig fields
// (DataDir, HTTPAddr, NodeID, ZAPPort) to the canonical
// kmsd container defaults. Env vars override empty fields.
//
// Identity-coupled fields — IAMEndpoint, JWKSURL, ExpectedIssuer,
// ExpectedAudience — are read from env only and never defaulted.
// validateProdConfigAtBoot rejects boot if any are empty, in every
// environment. The historical IAMEndpoint=https://hanzo.id default
// silently routed every white-label tenant service-account login to a
// foreign IAM and rejected every token, masking real outages — no env
// (dev, devnet, prod) gets a silent fallback anymore.
func applyEmbedDefaults(cfg EmbedConfig) EmbedConfig {
	if cfg.DataDir == "" {
		cfg.DataDir = envOr("KMS_DATA_DIR", "/data/hanzo-kms")
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = envOr("KMS_LISTEN", ":8443")
	}
	if cfg.NodeID == "" {
		cfg.NodeID = envOr("KMS_NODE_ID", "hanzo-kms-0")
	}
	if cfg.Env == "" {
		cfg.Env = envOr("KMS_ENV", "dev")
	}
	// Identity-coupled config is read from env only — never defaulted.
	// One canonical name per concept across every Hanzo service:
	//   IAM_URL        — the IAM origin
	//   IAM_ISSUER     — iss claim in JWTs (usually = IAM_URL)
	//   IAM_AUDIENCE   — aud claim this service accepts
	//   IAM_KEYS_URL   — JWKS URL (usually = IAM_URL/.well-known/jwks)
	// validateProdConfigAtBoot rejects boot if any are empty.
	if cfg.IAMEndpoint == "" {
		cfg.IAMEndpoint = strings.TrimSpace(os.Getenv("IAM_URL"))
	}
	if cfg.ExpectedIssuer == "" {
		cfg.ExpectedIssuer = strings.TrimSpace(os.Getenv("IAM_ISSUER"))
	}
	if cfg.ExpectedAudience == "" {
		cfg.ExpectedAudience = strings.TrimSpace(os.Getenv("IAM_AUDIENCE"))
	}
	if cfg.JWKSURL == "" && cfg.JWTKeySource == "" {
		cfg.JWKSURL = strings.TrimSpace(os.Getenv("IAM_KEYS_URL"))
	}
	if cfg.ZAPPort == 0 {
		// Honour env override; fall back to canonical 9999.
		if v := envOr("KMS_ZAP_PORT", strings.TrimPrefix(envOr("KMS_ZAP", ":9999"), ":")); v != "" {
			fmt.Sscanf(v, "%d", &cfg.ZAPPort)
		}
		if cfg.ZAPPort == 0 {
			cfg.ZAPPort = 9999
		}
	}
	return cfg
}

// validateProdConfigAtBoot rejects boot if identity-coupled config is
// missing. The hard-coded https://hanzo.id default silently routed
// every white-label tenant service-account login to the wrong IAM and
// rejected every token, masking real outages. There is no dev escape
// hatch — every Hanzo user (laptop, devnet, prod) gets the same
// contract: supply IAM_URL, IAM_ISSUER, IAM_AUDIENCE, IAM_KEYS_URL or
// refuse to boot.
func validateProdConfigAtBoot(cfg EmbedConfig) error {
	if strings.TrimSpace(cfg.IAMEndpoint) == "" {
		return fmt.Errorf("IAM_URL is required (no default) — point at the IAM you want this KMS to trust")
	}
	if strings.TrimSpace(cfg.ExpectedIssuer) == "" {
		return fmt.Errorf("IAM_ISSUER is required (no default) — set to the issuer URL the IAM stamps in its JWTs")
	}
	if strings.TrimSpace(cfg.ExpectedAudience) == "" {
		return fmt.Errorf("IAM_AUDIENCE is required (no default) — set to this KMS's audience claim")
	}
	jwks := strings.TrimSpace(cfg.JWKSURL)
	if jwks == "" {
		jwks = strings.TrimSpace(cfg.JWTKeySource)
	}
	if jwks == "" {
		return fmt.Errorf("IAM_KEYS_URL is required (no default) — set to where IAM publishes its signing keys")
	}
	return nil
}

// --- Header hygiene ---

// stripIdentityHeaders removes every inbound identity header before mux
// dispatch. The only headers honoured downstream are the canonical three —
// X-User-Id, X-Org-Id, X-Roles — injected by the Hanzo Gateway after JWKS
// verification. Every legacy variant (X-Hanzo-*, X-IAM-*, X-User-Role
// singular, X-Tenant-Id, X-Is-Admin, …) is dropped outright so a spoofed
// header cannot survive to a handler even if the cluster boundary is
// bypassed.
func stripIdentityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{
			// Canonical 3 — dropped, re-injected by gateway from verified JWT.
			"X-User-Id", "X-Org-Id", "X-Roles",
			// Informational.
			"X-User-Email",
			// Legacy gateway pre-validation hints — killed.
			"X-Gateway-Validated", "X-Gateway-User-Id", "X-Gateway-Org-Id", "X-Gateway-User-Email",
			// Legacy hanzo-prefixed variants — killed.
			"X-Hanzo-User-Id", "X-Hanzo-User-Email",
			"X-Hanzo-User-Role", "X-Hanzo-User-Roles", "X-Hanzo-User-IsAdmin",
			"X-Hanzo-Org", "X-Hanzo-Org-Id",
			// Legacy IAM-prefixed variants — killed.
			"X-IAM-User-Id", "X-IAM-Org", "X-IAM-Org-Id", "X-IAM-Roles",
			// Legacy singular / alias role headers — killed.
			"X-User-Role", "X-User-Roles",
			// Tenant aliases — killed.
			"X-Tenant-Id", "X-Tenant-ID", "X-Org",
			// Is-admin boolean — killed.
			"X-Is-Admin",
		} {
			r.Header.Del(h)
		}
		next.ServeHTTP(w, r)
	})
}

// methodAllowlist rejects TRACE/CONNECT/OPTIONS at the edge.
// Everything else is dispatched normally and handled per-route.
func methodAllowlist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodTrace, http.MethodConnect, http.MethodOptions:
			w.Header().Set("Allow", "GET, POST, PATCH, DELETE")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "method not allowed"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Routes ---

func registerHealth(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"service": "kms",
			"version": Version,
		})
	})
	// Canonical lux health path also gets a binding for parity with the
	// luxfi/kms surface; the standalone kmsd binary served only /healthz
	// historically, but the Hanzo gateway probes /v1/kms/health.
	mux.HandleFunc("GET /v1/kms/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"service": "kms",
			"version": Version,
		})
	})
}

func registerAuth(mux *http.ServeMux, iamEndpoint string) {
	// Bounded HTTP client — prevents slow IAM responses from holding goroutines.
	iamClient := &http.Client{Timeout: 10 * time.Second}

	mux.HandleFunc("POST /v1/kms/auth/login", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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
		resp, err := iamClient.PostForm(iamEndpoint+"/v1/iam/oauth/token", form)
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
}

// --- Authentication ---

// jwtClaims is the minimal set of verified JWT claims we extract.
// Verification (signature, alg, iss, aud, exp) happens in verifyJWT
// (auth.go).
//
// These are identity claims only. KMS derives no permission from them:
// IAM owns identity and permissions, and this package answers "who
// signed this token" — never "what may they reach". Authorization for
// the secret plane lives in cloud (apps/kms), which folds the caller's
// org into the storage key.
type jwtClaims struct {
	Iss   string `json:"iss"`
	Owner string `json:"owner"`
	Sub   string `json:"sub"`
}

// authorize extracts the bearer token and performs full RFC 7519
// verification: signature (via JWKS), alg allowlist (asymmetric only —
// no HS*, no none), iss, aud, exp. On any failure emits 401 with a
// generic body and logs a structured audit line with the failure class.
//
// The function NEVER falls back to unsigned parsing. It NEVER accepts
// alg=none. It NEVER honours an owner=="admin" shortcut. Upstream gateway
// verification is belt-and-braces — we verify independently in case the
// gateway is bypassed.
func authorize(w http.ResponseWriter, r *http.Request) (jwtClaims, bool) {
	claims, err := verifyJWT(r.Header.Get("Authorization"))
	if err != nil {
		authLog.Info("kms_auth_reject",
			"reason", authFailReason(err),
			"peer", peerIP(r),
			"method", r.Method,
			"path", r.URL.Path,
		)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "unauthorized"})
		return jwtClaims{}, false
	}
	return claims, true
}

// --- ZAP secrets server ---

// startZAPSecretServer brings up the binary ZAP transport for in-cluster
// secret CRUD. Disabled when:
//   - KMS_MASTER_KEY_B64 unset or invalid (no transport encryption key)
//   - KMS_ZAP_PORT/KMS_ZAP resolves to <=0
//   - no consensus authority snapshot configured (fail-soft: HTTP path
//     still up; ZAP comes online when kms-operator drops the snapshot)
//
// A configured-but-malformed snapshot is fatal (fail-closed on bad input).
// Returns the running node so Stop can shut it down.
func startZAPSecretServer(secStore *store.SecretStore, cfg EmbedConfig) *zap.Node {
	masterKeyB64 := envOr("KMS_MASTER_KEY_B64", "")
	if masterKeyB64 == "" || cfg.ZAPPort <= 0 {
		log.Info("kms.Embed: ZAP secrets-server disabled (set KMS_MASTER_KEY_B64 + KMS_ZAP_PORT/KMS_ZAP)")
		return nil
	}
	masterKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil || len(masterKey) != 32 {
		log.Info("kms.Embed: KMS_MASTER_KEY_B64 invalid (need 32 raw bytes base64); ZAP server disabled")
		return nil
	}
	authorizer, err := buildConsensusAuthorizer()
	if err != nil {
		log.Crit("kms.Embed: consensus authorizer config invalid (refusing to fail open)", "err", err)
		return nil
	}
	if authorizer == nil {
		log.Info("kms.Embed: no consensus authority snapshot configured; ZAP secrets-server disabled (HTTP path still up)",
			"file_env", envConsensusFile, "validators_env", envConsensusValidators, "operators_env", envConsensusOperators)
		return nil
	}
	n := zap.NewNode(zap.NodeConfig{
		NodeID:      cfg.NodeID + "-secrets",
		ServiceType: "_kms._tcp",
		Port:        cfg.ZAPPort,
	})
	if err := n.Start(); err != nil {
		log.Error("kms.Embed: ZAP secrets-server start failed", "port", cfg.ZAPPort, "err", err)
		return nil
	}
	zs := zapserver.New(zapserver.Config{
		Store:      secStore,
		MasterKey:  masterKey,
		Logger:     log.Root(),
		Authorizer: authorizer,
	})
	zs.Register(n)
	log.Info("kms.Embed: ZAP secrets-server listening", "port", cfg.ZAPPort, "service", "_kms._tcp")
	return n
}

// --- Replicator ---

func startReplicator(db *badger.DB, nodeID string) *badger.Replicator {
	rawEndpoint := os.Getenv("REPLICATE_S3_ENDPOINT")
	if rawEndpoint == "" {
		log.Info("kms.Embed: S3 replication disabled (set REPLICATE_S3_ENDPOINT to enable)")
		return nil
	}
	endpoint, useSSL := normalizeS3Endpoint(rawEndpoint)
	access := firstNonEmpty(
		os.Getenv("REPLICATE_S3_ACCESS_KEY_ID"),
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("REPLICATE_S3_ACCESS_KEY"),
	)
	secret := firstNonEmpty(
		os.Getenv("REPLICATE_S3_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("REPLICATE_S3_SECRET_KEY"),
	)
	cfg := badger.ReplicatorConfig{
		Endpoint:  endpoint,
		Bucket:    envOr("REPLICATE_S3_BUCKET", "hanzo-kms-backups"),
		Region:    envOr("REPLICATE_S3_REGION", "us-central1"),
		AccessKey: access,
		SecretKey: secret,
		UseSSL:    useSSL,
		Path:      envOr("REPLICATE_S3_PATH", envOr("REPLICATE_PATH", fmt.Sprintf("kms/%s", nodeID))),
		Interval:  time.Second,
	}
	if os.Getenv("REPLICATE_AGE_RECIPIENT") != "" {
		log.Info("kms.Embed: S3 replication with age encryption enabled")
	}
	r, err := badger.NewReplicator(db, cfg)
	if err != nil {
		log.Warn("kms.Embed: S3 replicator init failed — replication disabled", "err", err)
		return nil
	}
	go r.Start(context.Background())
	log.Info("kms.Embed: S3 replication started",
		"endpoint", endpoint,
		"bucket", cfg.Bucket,
		"path", cfg.Path)
	return r
}

// --- Helpers ---

func masterKeyFromEnv() []byte {
	b64 := os.Getenv("KMS_ENCRYPTION_KEY_B64")
	if b64 == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) != 32 {
		log.Info("kms.Embed: KMS_ENCRYPTION_KEY_B64 invalid (need 32 bytes base64); at-rest encryption disabled")
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

// firstNonEmpty returns the first argument with non-zero length, or "".
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// normalizeS3Endpoint strips scheme + path from REPLICATE_S3_ENDPOINT so
// minio.New receives the bare host:port it expects. Returns (host[:port],
// useSSL). Logs a warning if the operator passed a path-bearing URL —
// the historical failure mode was silent disablement of replication.
func normalizeS3Endpoint(raw string) (host string, useSSL bool) {
	useSSL = !strings.HasPrefix(raw, "http://")
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			log.Warn("kms.Embed: REPLICATE_S3_ENDPOINT failed to parse — using as-is, replication may fail", "endpoint", raw)
			return raw, useSSL
		}
		if u.Path != "" && u.Path != "/" {
			log.Warn("kms.Embed: REPLICATE_S3_ENDPOINT has a path component — stripping; put the bucket in REPLICATE_S3_BUCKET", "endpoint", raw, "path", u.Path)
		}
		if u.RawQuery != "" {
			log.Warn("kms.Embed: REPLICATE_S3_ENDPOINT has a query string — stripping", "endpoint", raw)
		}
		return u.Host, useSSL
	}
	return strings.TrimRight(raw, "/"), useSSL
}

// --- ZapDB logger adapter ---
//
// ZapDB expects an Errorf/Warningf/Infof/Debugf surface (badger's
// Logger interface). luxfi/log is the Hanzo-wide logging library;
// we adapt its variadic API to ZapDB's format-string API.

type zapdbLogger struct{}

func (zapdbLogger) Errorf(format string, args ...interface{}) {
	log.Error(fmt.Sprintf(format, args...))
}
func (zapdbLogger) Warningf(format string, args ...interface{}) {
	log.Warn(fmt.Sprintf(format, args...))
}
func (zapdbLogger) Infof(format string, args ...interface{}) {
	log.Info(fmt.Sprintf(format, args...))
}
func (zapdbLogger) Debugf(format string, args ...interface{}) {
	log.Debug(fmt.Sprintf(format, args...))
}

// registerFrontend adds a catch-all `/` handler that serves the React
// SPA from KMS_FRONTEND_DIR (set by the Dockerfile to /app/frontend).
//
// The mux is already populated with explicit API routes (/healthz,
// /v1/kms/**, /v1/mpc/**) — those take precedence because Go's
// ServeMux longest-match-wins rule fires the more-specific pattern
// before this one.
//
// Static assets resolve directly from disk. Anything else (e.g.
// /login, /dashboard) returns index.html so the React Router can
// handle client-side routing without a server round-trip.
//
// If KMS_FRONTEND_DIR is unset OR doesn't contain index.html, the
// handler returns a tiny JSON status object — preserves the
// "no UI here, but the service is alive" signal we used to get
// from the bare 404 without surprising operators.
func registerFrontend(mux *http.ServeMux) {
	dir := strings.TrimSpace(os.Getenv("KMS_FRONTEND_DIR"))
	indexPath := ""
	if dir != "" {
		candidate := dir + "/index.html"
		if _, err := os.Stat(candidate); err == nil {
			indexPath = candidate
		}
	}

	if indexPath == "" {
		// Fallback: tiny JSON service banner for when the SPA isn't bundled.
		mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"service": "kms",
				"version": Version,
				"status":  "ok",
				"docs":    "/v1/kms",
			})
		})
		return
	}

	fileServer := http.FileServer(http.Dir(dir))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// API paths starting with /v1/ or /healthz never reach here —
		// ServeMux fires the more-specific handler first. Defense in
		// depth: bail out if the path looks like an API route.
		//
		// /api/ is explicitly 404'd: this service has ZERO /api/ surface
		// (the ONE canonical prefix is /v1/kms). Without this guard the SPA
		// fallback below would answer GET /api/v1/... with index.html (200),
		// masquerading as a live legacy /api/ backend. There is no /api/;
		// make that unambiguous at the wire.
		if strings.HasPrefix(r.URL.Path, "/v1/") ||
			strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" ||
			r.URL.Path == "/healthz" || r.URL.Path == "/health" {
			http.NotFound(w, r)
			return
		}
		// SPA fallback: serve index.html for any path that isn't a
		// concrete file on disk. This is the standard React Router
		// pattern (matches Vite's default dev-server behaviour).
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" {
			http.ServeFile(w, r, indexPath)
			return
		}
		if _, err := os.Stat(dir + "/" + clean); err != nil {
			http.ServeFile(w, r, indexPath)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
