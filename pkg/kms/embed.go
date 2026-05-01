// Package kms is the in-process Hanzo KMS server. It is a thin wrapper
// over github.com/luxfi/kms with Hanzo-specific defaults (port 8443,
// /data/hanzo-kms, IAM at https://hanzo.id), JWT verification (RFC 7519,
// no HS*, no alg=none), audit log with composite actor_id, version CAS
// for replay-resistant updates, and identity-header hygiene.
//
// All threshold signing is delegated to the MPC daemon over ZAP
// (cfg.MPCAddr, cfg.MPCVaultID). All secret storage uses ZapDB at
// cfg.DataDir with optional at-rest encryption via KMS_ENCRYPTION_KEY_B64
// and the in-process Replicator streaming encrypted backups to S3.
//
// This file owns the route assembly + transport wiring. embed.go exposes
// the canonical Embed(ctx, cfg) (*Embedded, error) entry point that the
// fused hanzo binary will import alongside iam, base, and tasks.
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

	"github.com/luxfi/kms/pkg/keys"
	"github.com/luxfi/kms/pkg/mpc"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/kms/pkg/zapserver"
	"github.com/luxfi/log"
	"github.com/luxfi/zap"
)

// Version is overridden at build time via -ldflags "-X
// github.com/hanzoai/kms/pkg/kms.Version=...".
var Version = "dev"

// maxBodyBytes caps every POST body to prevent OOM via slowloris-style upload.
const maxBodyBytes = 1 << 20 // 1 MiB

// globalAuditor receives one entry per KMS request. Created in Embed,
// consumed by registerSecretRoutes. nil-safe (see auditor.record).
//
// This is a process-global because the auth-failure paths in
// authorize() also need to call recordAudit, and threading the auditor
// into every handler would spread the package surface needlessly. The
// fused hanzo binary calls Embed exactly once, so the global is fine.
var globalAuditor *auditor

// EmbedConfig configures the in-process Hanzo KMS server.
//
// Zero values resolve to the production defaults that match the
// canonical kmsd container image (DataDir=/data/hanzo-kms,
// HTTPAddr=:8443, IAMEndpoint=https://hanzo.id, ZAPPort=9999).
type EmbedConfig struct {
	// DataDir is the ZapDB persistence root.
	// Empty → "/data/hanzo-kms" (production default).
	DataDir string

	// HTTPAddr is the bind address for the HTTP server.
	// Empty → ":8443". Use ":0" for an ephemeral port (tests).
	HTTPAddr string

	// IAMEndpoint is the Hanzo IAM origin used for the
	// /v1/kms/auth/login client_credentials proxy.
	// Empty → "https://hanzo.id".
	IAMEndpoint string

	// JWKSURL is the JWKS endpoint for verifying inbound JWTs.
	// Empty → IAMEndpoint + "/.well-known/jwks". Tests can point this
	// at an httptest.Server.
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

	// Env names the deployment environment. "dev"/"devnet"/"local"
	// tolerate missing JWT config; anything else refuses to boot
	// without KMS_EXPECTED_ISSUER, KMS_EXPECTED_AUDIENCE, KMS_JWKS_URL.
	// Empty → "dev".
	Env string

	// ExpectedIssuer is the iss claim a JWT must carry. Empty →
	// $KMS_EXPECTED_ISSUER.
	ExpectedIssuer string

	// ExpectedAudience is the aud claim a JWT must carry (comma list
	// allowed). Empty → $KMS_EXPECTED_AUDIENCE or "kms".
	ExpectedAudience string

	// MPCAddr is the MPC daemon network address. Empty → mDNS only.
	MPCAddr string

	// MPCVaultID enables the threshold-signing key routes when set.
	MPCVaultID string

	// AuditDB is the SQLite path for the audit ledger. Empty →
	// $KMS_AUDIT_DB or "/tmp/kms-aux.db".
	AuditDB string

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

	db          *badger.DB
	replicator  *badger.Replicator
	auditCancel context.CancelFunc
	zapNode     *zap.Node // nil when ZAP server disabled

	httpAddr string // bound listener address (post-:0 resolution)
}

// Embed boots the Hanzo KMS server in-process and returns a handle.
//
// Embed is safe to call exactly once per process: it registers
// process-global JWT verification config and a single audit-writer
// goroutine. The fused hanzo binary calls Embed once at startup and
// keeps the handle for the lifetime of the process.
//
// The provided ctx is used for cancellation; if ctx is cancelled before
// Stop is called, Embed shuts the server down automatically.
func Embed(ctx context.Context, cfg EmbedConfig) (*Embedded, error) {
	cfg = applyEmbedDefaults(cfg)

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

	auditCtx, auditCancel := context.WithCancel(context.Background())
	em.auditCancel = auditCancel
	globalAuditor = newAuditor(auditCtx, cfg.AuditDB)

	secStore := store.NewSecretStore(db)

	mux := http.NewServeMux()
	registerHealth(mux)
	registerAuth(mux, cfg.IAMEndpoint)
	registerSecretRoutes(mux, secStore, db)

	if cfg.MPCVaultID != "" {
		registerKeyRoutes(mux, db, cfg)
	} else {
		log.Info("kms.Embed: MPC_VAULT_ID empty — secrets-only mode (no threshold signing)")
	}

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
		em.httpAddr = cfg.HTTPAddr
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

// HTTPAddr returns the bound listen address. Returns "" when
// SkipListen=true or before the listener has been wired.
func (e *Embedded) HTTPAddr() string {
	if e == nil || e.cfg.SkipListen {
		return ""
	}
	return e.httpAddr
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
	if e.auditCancel != nil {
		e.auditCancel()
		e.auditCancel = nil
	}
	if e.db != nil {
		_ = e.db.Close()
		e.db = nil
	}
	log.Info("kms.Embed: stopped")
	return nil
}

// applyEmbedDefaults resolves zero-value EmbedConfig fields to the
// canonical Hanzo defaults. Env vars override empty fields so the
// standalone kmsd path keeps working unmodified.
func applyEmbedDefaults(cfg EmbedConfig) EmbedConfig {
	if cfg.DataDir == "" {
		cfg.DataDir = envOr("KMS_DATA_DIR", "/data/hanzo-kms")
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = envOr("KMS_LISTEN", ":8443")
	}
	if cfg.IAMEndpoint == "" {
		cfg.IAMEndpoint = envOr("IAM_ENDPOINT", "https://hanzo.id")
	}
	if cfg.NodeID == "" {
		cfg.NodeID = envOr("KMS_NODE_ID", "hanzo-kms-0")
	}
	if cfg.Env == "" {
		cfg.Env = envOr("KMS_ENV", "dev")
	}
	if cfg.ExpectedIssuer == "" {
		cfg.ExpectedIssuer = strings.TrimSpace(os.Getenv("KMS_EXPECTED_ISSUER"))
	}
	if cfg.ExpectedAudience == "" {
		cfg.ExpectedAudience = envOr("KMS_EXPECTED_AUDIENCE", "kms")
	}
	if cfg.JWKSURL == "" && cfg.JWTKeySource == "" {
		cfg.JWKSURL = strings.TrimSpace(os.Getenv("KMS_JWKS_URL"))
	}
	if cfg.MPCAddr == "" {
		cfg.MPCAddr = envOr("MPC_ADDR", "")
	}
	if cfg.MPCVaultID == "" {
		cfg.MPCVaultID = envOr("MPC_VAULT_ID", "")
	}
	if cfg.AuditDB == "" {
		cfg.AuditDB = envOr("KMS_AUDIT_DB", "/tmp/kms-aux.db")
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
		resp, err := iamClient.PostForm(iamEndpoint+"/api/login/oauth/access_token", form)
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

// registerSecretRoutes mounts the canonical lux/kms HTTP secret CRUD at
// /v1/kms/orgs/{org}/secrets/... — one path, one way.
//
// R-3 (replay protection): POST (create/upsert) always bumps the version.
// PATCH (update) requires If-Match or body.version matching current; a
// replayed PATCH after rotation returns 409.
//
// R-12 (audit trail): every request emits one audit row with composite
// actor_id "iss:sub". See audit.go for details.
func registerSecretRoutes(mux *http.ServeMux, secStore *store.SecretStore, db *badger.DB) {
	get := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authorize(w, r)
		if !ok {
			recordAudit(claims, r, "", "", "", http.StatusUnauthorized, 0)
			return
		}
		orgURL := r.PathValue("org")
		if !claims.canActOnOrg(orgURL) {
			writeJSON(w, http.StatusForbidden, map[string]any{"message": "org claim does not match URL"})
			recordAudit(claims, r, "", "", "", http.StatusForbidden, 0)
			return
		}
		rest := r.PathValue("rest")
		path, name, ok := splitSecretPath(w, rest)
		if !ok {
			recordAudit(claims, r, "", "", "", http.StatusBadRequest, 0)
			return
		}
		env := r.URL.Query().Get("env")
		if env == "" {
			env = "default"
		}
		sec, err := secStore.Get(path, name, env)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			recordAudit(claims, r, path, name, env, http.StatusNotFound, 0)
			return
		}
		curVer, _ := readVersion(db, path, name, env)
		writeJSON(w, http.StatusOK, map[string]any{
			"secret":  map[string]any{"value": string(sec.Ciphertext)},
			"version": curVer,
		})
		recordAudit(claims, r, path, name, env, http.StatusOK, 0)
	}

	put := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authorize(w, r)
		if !ok {
			recordAudit(claims, r, "", "", "", http.StatusUnauthorized, 0)
			return
		}
		orgURL := r.PathValue("org")
		if !claims.canActOnOrg(orgURL) {
			writeJSON(w, http.StatusForbidden, map[string]any{"message": "org claim does not match URL"})
			recordAudit(claims, r, "", "", "", http.StatusForbidden, 0)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var req struct {
			Path  string `json:"path"`
			Name  string `json:"name"`
			Env   string `json:"env"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "name and value required"})
			recordAudit(claims, r, req.Path, req.Name, req.Env, http.StatusBadRequest, 0)
			return
		}
		if !safePath(req.Path) || !safePath(req.Name) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid path or name"})
			recordAudit(claims, r, req.Path, req.Name, req.Env, http.StatusBadRequest, 0)
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
			recordAudit(claims, r, req.Path, req.Name, req.Env, http.StatusInternalServerError, 0)
			return
		}
		// POST is upsert — do NOT enforce CAS. Bump version by passing -1.
		newVer, verErr := bumpVersion(db, req.Path, req.Name, req.Env, -1)
		if verErr != nil {
			log.Warn("kms: version bump failed after put", "err", verErr)
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "version": newVer})
		recordAudit(claims, r, req.Path, req.Name, req.Env, http.StatusCreated, newVer)
	}

	patch := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authorize(w, r)
		if !ok {
			recordAudit(claims, r, "", "", "", http.StatusUnauthorized, 0)
			return
		}
		orgURL := r.PathValue("org")
		if !claims.canActOnOrg(orgURL) {
			writeJSON(w, http.StatusForbidden, map[string]any{"message": "org claim does not match URL"})
			recordAudit(claims, r, "", "", "", http.StatusForbidden, 0)
			return
		}
		rest := r.PathValue("rest")
		path, name, ok := splitSecretPath(w, rest)
		if !ok {
			recordAudit(claims, r, "", "", "", http.StatusBadRequest, 0)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var req struct {
			Value   string `json:"value"`
			Version *int64 `json:"version"` // pointer: distinguish 0 from "missing"
			Env     string `json:"env"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "value required"})
			recordAudit(claims, r, path, name, req.Env, http.StatusBadRequest, 0)
			return
		}
		env := req.Env
		if env == "" {
			env = r.URL.Query().Get("env")
		}
		if env == "" {
			env = "default"
		}
		// Version CAS: require EITHER If-Match header OR body.version. If
		// both are present they must agree. Missing both → 428 Precondition
		// Required: PATCH is explicitly CAS; an unauthenticated rotation
		// is exactly the replay vector.
		var expected int64 = -1
		if h := strings.TrimSpace(r.Header.Get("If-Match")); h != "" {
			var v int64
			if _, err := fmt.Sscanf(strings.Trim(h, `"`), "%d", &v); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"message": "If-Match must be integer version"})
				recordAudit(claims, r, path, name, env, http.StatusBadRequest, 0)
				return
			}
			expected = v
		}
		if req.Version != nil {
			if expected >= 0 && expected != *req.Version {
				writeJSON(w, http.StatusBadRequest, map[string]any{"message": "If-Match and body.version disagree"})
				recordAudit(claims, r, path, name, env, http.StatusBadRequest, 0)
				return
			}
			expected = *req.Version
		}
		if expected < 0 {
			writeJSON(w, http.StatusPreconditionRequired, map[string]any{
				"message": "PATCH requires If-Match header or body.version",
			})
			recordAudit(claims, r, path, name, env, http.StatusPreconditionRequired, 0)
			return
		}
		// Ensure the secret exists before attempting CAS — otherwise an
		// attacker with a stale "version 1" envelope could CREATE a secret
		// via PATCH. PATCH is update-only by contract.
		if _, err := secStore.Get(path, name, env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			recordAudit(claims, r, path, name, env, http.StatusNotFound, 0)
			return
		}
		newVer, verErr := bumpVersion(db, path, name, env, expected)
		if errors.Is(verErr, ErrVersionMismatch) {
			cur, _ := readVersion(db, path, name, env)
			writeJSON(w, http.StatusConflict, map[string]any{
				"message":         "version mismatch — replayed or stale update",
				"currentVersion":  cur,
				"expectedVersion": expected,
			})
			recordAudit(claims, r, path, name, env, http.StatusConflict, cur)
			return
		}
		if verErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"message": verErr.Error()})
			recordAudit(claims, r, path, name, env, http.StatusInternalServerError, 0)
			return
		}
		sec := &store.Secret{
			Name:       name,
			Path:       path,
			Env:        env,
			Ciphertext: []byte(req.Value),
		}
		if err := secStore.Put(sec); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"message": err.Error()})
			recordAudit(claims, r, path, name, env, http.StatusInternalServerError, 0)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": newVer})
		recordAudit(claims, r, path, name, env, http.StatusOK, newVer)
	}

	del := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authorize(w, r)
		if !ok {
			recordAudit(claims, r, "", "", "", http.StatusUnauthorized, 0)
			return
		}
		orgURL := r.PathValue("org")
		if !claims.canActOnOrg(orgURL) {
			writeJSON(w, http.StatusForbidden, map[string]any{"message": "org claim does not match URL"})
			recordAudit(claims, r, "", "", "", http.StatusForbidden, 0)
			return
		}
		rest := r.PathValue("rest")
		path, name, ok := splitSecretPath(w, rest)
		if !ok {
			recordAudit(claims, r, "", "", "", http.StatusBadRequest, 0)
			return
		}
		env := r.URL.Query().Get("env")
		if env == "" {
			env = "default"
		}
		if err := secStore.Delete(path, name, env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			recordAudit(claims, r, path, name, env, http.StatusNotFound, 0)
			return
		}
		// Clear version record so a re-create starts from 1 again.
		_ = deleteVersion(db, path, name, env)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		recordAudit(claims, r, path, name, env, http.StatusOK, 0)
	}

	// Canonical (lux native).
	mux.HandleFunc("GET /v1/kms/orgs/{org}/secrets/{rest...}", get)
	mux.HandleFunc("POST /v1/kms/orgs/{org}/secrets", put)
	mux.HandleFunc("PATCH /v1/kms/orgs/{org}/secrets/{rest...}", patch)
	mux.HandleFunc("DELETE /v1/kms/orgs/{org}/secrets/{rest...}", del)

	// Env-backed legacy fetch — admin-only. Reads any process env var, so it
	// MUST NOT be available to a tenant-scoped JWT. Only callers carrying a
	// role of "superadmin" or "kms-admin" may use it; everyone else gets 403.
	mux.HandleFunc("GET /v1/kms/secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authorize(w, r)
		if !ok {
			recordAudit(claims, r, "", "", "", http.StatusUnauthorized, 0)
			return
		}
		if !claims.isAdmin() {
			writeJSON(w, http.StatusForbidden, map[string]any{"message": "admin role required"})
			recordAudit(claims, r, "", "", "", http.StatusForbidden, 0)
			return
		}
		name := r.PathValue("name")
		if !safeEnvName(name) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid name"})
			recordAudit(claims, r, "", name, "", http.StatusBadRequest, 0)
			return
		}
		val := os.Getenv(name)
		if val == "" {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
			recordAudit(claims, r, "", name, "", http.StatusNotFound, 0)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"secret": map[string]any{"secretKey": name, "secretValue": val},
		})
		recordAudit(claims, r, "", name, "", http.StatusOK, 0)
	})

	// Audit stats endpoint — admin only.
	mux.HandleFunc("GET /v1/kms/audit/stats", func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authorize(w, r)
		if !ok {
			return
		}
		if !claims.isAdmin() {
			writeJSON(w, http.StatusForbidden, map[string]any{"message": "admin role required"})
			return
		}
		written, dropped := globalAuditor.stats()
		writeJSON(w, http.StatusOK, map[string]any{"written": written, "dropped": dropped})
	})
}

// recordAudit is a small helper that emits one audit row per handler
// call. Pulls method/path from the request, derives actor_id from the
// JWT claims via composeActorID, and queues the entry to the background
// writer. Safe to call with empty claims (unauthenticated requests).
func recordAudit(claims jwtClaims, r *http.Request, secretPath, secretName, env string, status int, newVersion int64) {
	if globalAuditor == nil {
		return
	}
	globalAuditor.record(auditEntry{
		TS:         time.Now().UTC(),
		ActorID:    composeActorID(claims.Iss, claims.Sub),
		Issuer:     claims.Iss,
		Subject:    claims.Sub,
		ActorRole:  firstRole(claims.Roles),
		Owner:      claims.Owner,
		Method:     r.Method,
		Path:       r.URL.Path,
		SecretPath: secretPath,
		SecretName: secretName,
		Env:        env,
		Result:     status,
		Version:    newVersion,
	})
}

func registerKeyRoutes(mux *http.ServeMux, db *badger.DB, cfg EmbedConfig) {
	// MPC connectivity is best-effort: if the MPC daemon is unreachable at
	// boot (common on devnet when MPC restarts or ZAP service is not yet
	// exposed), log a warning and run in secrets-only mode rather than
	// crash-looping the pod. Readiness probe must keep passing so secrets
	// routes (the majority of traffic) stay online. Threshold-signing key
	// routes will return 503 via zapClient.Status() checks downstream.
	zapClient, err := mpc.NewZapClient(cfg.NodeID, cfg.MPCAddr)
	if err != nil {
		log.Warn("kms: mpc zap client init failed — secrets-only mode, key routes disabled", "err", err)
		return
	}
	keyStore, err := store.New(db)
	if err != nil {
		log.Crit("kms: key store", "err", err)
	}

	checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if status, err := zapClient.Status(checkCtx); err != nil {
		log.Warn("kms: mpc unreachable", "err", err)
	} else {
		log.Info("kms: mpc status",
			"ready", status.Ready,
			"peers", status.ConnectedPeers,
			"expected", status.ExpectedPeers,
			"mode", status.Mode)
	}
	cancel()

	mgr := keys.NewManager(zapClient, keyStore, cfg.MPCVaultID)

	// Admin gate for every key route: authorize() (full JWT verify) →
	// isAdmin() (explicit role claim). No route is reachable without
	// both checks passing. Red F5: registerKeyRoutes had NO auth at all
	// prior to this patch.
	adminOnly := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims, ok := authorize(w, r)
			if !ok {
				return
			}
			if !claims.isAdmin() {
				writeJSON(w, http.StatusForbidden, map[string]any{"message": "admin role required"})
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("POST /v1/kms/keys/generate", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var req keys.GenerateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if req.ValidatorID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validator_id is required"})
			return
		}
		if req.Threshold < 2 || req.Parties < req.Threshold {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid threshold/parties"})
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

	mux.HandleFunc("GET /v1/kms/keys", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		list := mgr.List()
		if list == nil {
			list = []*keys.ValidatorKeySet{}
		}
		writeJSON(w, http.StatusOK, list)
	}))

	mux.HandleFunc("GET /v1/kms/keys/{id}", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		ks, err := mgr.Get(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, ks)
	}))

	mux.HandleFunc("POST /v1/kms/keys/{id}/sign", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		id := r.PathValue("id")
		var req keys.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Message) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
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
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key_type must be bls or ringtail"})
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

	mux.HandleFunc("POST /v1/kms/keys/{id}/rotate", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		id := r.PathValue("id")
		var req keys.RotateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		ks, err := mgr.Rotate(r.Context(), id, req)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ks)
	}))

	mux.HandleFunc("GET /v1/kms/status", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		st, err := zapClient.Status(r.Context())
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"kms": "ok", "mpc": "unreachable", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"kms": "ok", "mpc": st})
	}))
}

// --- Authorization ---

// jwtClaims is the minimal set of verified JWT claims we extract for
// authorization. Verification (signature, alg, iss, aud, exp) happens
// in verifyJWT (auth.go).
type jwtClaims struct {
	Iss   string   `json:"iss"`
	Owner string   `json:"owner"`
	Sub   string   `json:"sub"`
	Roles []string `json:"roles"`
}

// canActOnOrg returns true if the bearer can act on the URL's org segment.
// Exactly two paths grant access:
//
//  1. The bearer's verified `owner` claim equals the URL org segment.
//  2. The bearer's verified `roles` claim contains "superadmin",
//     "kms-admin", or "admin".
//
// There is no owner=="admin" shortcut. Casdoor emits owner="admin" for
// every service account in its superuser-app namespace — treating that
// string as a cross-tenant grant makes every IAM service account a root
// key over every org. Red demonstrated this live on 2026-04-21.
func (c jwtClaims) canActOnOrg(org string) bool {
	if c.isAdmin() {
		return true
	}
	return c.Owner != "" && org != "" && c.Owner == org
}

// isAdmin checks for an explicit superadmin role. The owner claim is a
// scoping field, not a privilege flag — keep the two concepts separate.
func (c jwtClaims) isAdmin() bool {
	for _, r := range c.Roles {
		switch strings.ToLower(strings.TrimSpace(r)) {
		case "superadmin", "kms-admin", "admin":
			return true
		}
	}
	return false
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

// splitSecretPath separates "rest" into (path, name) and rejects any
// traversal/control-byte attempts. Returns ok=false after writing 400.
func splitSecretPath(w http.ResponseWriter, rest string) (string, string, bool) {
	if !safePath(rest) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid path"})
		return "", "", false
	}
	idx := strings.LastIndex(rest, "/")
	if idx < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "path and name required"})
		return "", "", false
	}
	return rest[:idx], rest[idx+1:], true
}

// safePath rejects path-traversal, double-slash collapsing, and control bytes.
// Allowed: ASCII alnum, '_', '-', '.', '/'. Disallowed segments: "" and "..".
func safePath(p string) bool {
	if p == "" {
		return true // optional fields
	}
	if strings.Contains(p, "//") || strings.Contains(p, "\x00") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for _, ch := range seg {
			switch {
			case ch >= 'a' && ch <= 'z':
			case ch >= 'A' && ch <= 'Z':
			case ch >= '0' && ch <= '9':
			case ch == '_' || ch == '-' || ch == '.':
			default:
				return false
			}
		}
	}
	return true
}

// safeEnvName matches POSIX env-var name rules: [A-Za-z_][A-Za-z0-9_]*.
func safeEnvName(n string) bool {
	if n == "" {
		return false
	}
	for i, ch := range n {
		switch {
		case ch >= 'A' && ch <= 'Z':
		case ch >= 'a' && ch <= 'z':
		case ch == '_':
		case i > 0 && ch >= '0' && ch <= '9':
		default:
			return false
		}
	}
	return true
}

// --- ZAP secrets server ---

// startZAPSecretServer brings up the binary ZAP transport for in-cluster
// secret CRUD. Disabled when KMS_MASTER_KEY_B64 is unset or the port
// resolves to <=0. Returns the running node so Stop can shut it down.
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
		Store:     secStore,
		MasterKey: masterKey,
		Logger:    log.Root(),
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
		if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/healthz" || r.URL.Path == "/health" {
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
