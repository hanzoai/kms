// Package zapsrv exposes the KMS secret CRUD surface over the ZAP binary
// protocol. Sub-100us in-cluster, same authorization model as the HTTP
// surface (IAM JWT validated against JWKS, identical role checks).
//
// Wire format (all multi-byte integers big-endian per zap library, all field
// offsets are byte positions inside a single root object):
//
//	OpcodeSecretResolve (0x0060):
//	  req:  token@0(Text), tenantId@8(Text), path@16(Text), name@24(Text)
//	  resp: status@0(Uint32), secretId@8(Text), error@16(Text)
//
//	OpcodeSecretGet (0x0061):
//	  req:  token@0(Text), secretId@8(Text)
//	  resp: status@0(Uint32), value@8(Bytes), error@16(Text)
//
//	OpcodeSecretCreate (0x0062):
//	  req:  token@0(Text), tenantId@8(Text), path@16(Text), name@24(Text),
//	        value@32(Bytes), secretType@40(Text)
//	  resp: status@0(Uint32), secretId@8(Text), error@16(Text)
//
//	OpcodeSecretUpdate (0x0063):
//	  req:  token@0(Text), secretId@8(Text), value@16(Bytes)
//	  resp: status@0(Uint32), error@8(Text)
//
//	OpcodeSecretDelete (0x0064):
//	  req:  token@0(Text), secretId@8(Text)
//	  resp: status@0(Uint32), error@8(Text)
//
// Authorization mirrors the HTTP path exactly:
//   - Token is parsed + signature-verified against the same JWKSValidator.
//   - Resolve/Get use canReadSecret(claims, tenantID).
//   - Create/Update/Delete use isSecretAdmin(claims, tenantID).
//   - Token is required even when AuthMode == "none" rejects callers (the
//     ZAP surface refuses to start without a JWKS validator — there is no
//     "none" escape hatch for the binary transport, by design).
package zapsrv

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/luxfi/zap"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/store"
)

// Opcodes for the KMS secret surface. Distinct from MPC (0x0001..0x0020) and
// from Tasks (0x0050..0x0051).
const (
	OpcodeSecretResolve uint16 = 0x0060
	OpcodeSecretGet     uint16 = 0x0061
	OpcodeSecretCreate  uint16 = 0x0062
	OpcodeSecretUpdate  uint16 = 0x0063
	OpcodeSecretDelete  uint16 = 0x0064
)

// Field offsets (kept small, fixed, and dense — no embedded sub-objects so
// the zero-copy reader can compute every value with a single bounds check).
const (
	reqFieldToken      = 0
	reqFieldTenantID   = 8
	reqFieldSecretID   = 8 // alt: get/update/delete carry secretId at slot 8
	reqFieldPath       = 16
	reqFieldName       = 24
	reqFieldValue      = 32 // create
	reqFieldUpdValue   = 16 // update places value right after secretId
	reqFieldSecretType = 40

	respFieldStatus   = 0
	respFieldSecretID = 8 // resolve/create
	respFieldValue    = 8 // get
	respFieldError16  = 16
	respFieldError8   = 8 // update/delete (no payload, error sits at slot 8)
)

// authorization status codes (mirror the HTTP shape).
const (
	statusOK           uint32 = 200
	statusBadRequest   uint32 = 400
	statusUnauthorized uint32 = 401
	statusForbidden    uint32 = 403
	statusNotFound     uint32 = 404
	statusServerError  uint32 = 500
)

// Server is the ZAP listener that mirrors the KMS HTTP secret surface.
type Server struct {
	node    *zap.Node
	port    int
	logger  *slog.Logger
	jwks    *auth.JWKSValidator
	secrets *store.ServiceSecretStore
	audit   *store.AuditStore
}

// Config builds a Server.
type Config struct {
	NodeID  string
	Port    int
	Logger  *slog.Logger
	JWKS    *auth.JWKSValidator
	Secrets *store.ServiceSecretStore
	Audit   *store.AuditStore
}

// New creates a Server with the given dependencies. Returns an error if any
// required field is missing — the binary transport refuses to start without
// a JWKS validator. There is no "no-auth" mode for ZAP.
func New(cfg Config) (*Server, error) {
	if cfg.JWKS == nil {
		return nil, errors.New("zapsrv: JWKS validator is required (no auth-disabled mode for binary transport)")
	}
	if cfg.Secrets == nil {
		return nil, errors.New("zapsrv: secrets store is required")
	}
	if cfg.Audit == nil {
		return nil, errors.New("zapsrv: audit store is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	nodeID := cfg.NodeID
	if nodeID == "" {
		nodeID = "kms-zap"
	}
	port := cfg.Port
	if port == 0 {
		port = 9653
	}
	node := zap.NewNode(zap.NodeConfig{
		NodeID:      nodeID,
		ServiceType: "_kms-secrets._tcp",
		Port:        port,
		Logger:      logger,
		NoDiscovery: true,
	})
	return &Server{
		node:    node,
		port:    port,
		logger:  logger,
		jwks:    cfg.JWKS,
		secrets: cfg.Secrets,
		audit:   cfg.Audit,
	}, nil
}

// Start registers handlers and starts the listener. Idempotent on the
// underlying zap.Node — caller should still only call once.
func (s *Server) Start() error {
	s.node.Handle(OpcodeSecretResolve, s.handleResolve)
	s.node.Handle(OpcodeSecretGet, s.handleGet)
	s.node.Handle(OpcodeSecretCreate, s.handleCreate)
	s.node.Handle(OpcodeSecretUpdate, s.handleUpdate)
	s.node.Handle(OpcodeSecretDelete, s.handleDelete)
	if err := s.node.Start(); err != nil {
		return fmt.Errorf("zapsrv: start: %w", err)
	}
	s.logger.Info("kms: ZAP secrets server listening", "port", s.port)
	return nil
}

// Stop closes the listener.
func (s *Server) Stop() {
	if s != nil && s.node != nil {
		s.node.Stop()
	}
}

// ── Handlers ────────────────────────────────────────────────────────────

func (s *Server) handleResolve(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	root := msg.Root()
	token := root.Text(reqFieldToken)
	tenantID := root.Text(reqFieldTenantID)
	path := root.Text(reqFieldPath)
	name := root.Text(reqFieldName)

	claims, status, errMsg := s.authn(token)
	if status != statusOK {
		return s.respWithSecretID(status, "", errMsg), nil
	}
	if tenantID == "" || path == "" || name == "" {
		return s.respWithSecretID(statusBadRequest, "", "tenantId, path, name required"), nil
	}
	if !canReadSecretFromAuth(claims, tenantID) {
		return s.respWithSecretID(statusForbidden, "", "forbidden"), nil
	}
	sec, err := s.secrets.Get(tenantID, path, name)
	if err != nil {
		return s.respWithSecretID(statusNotFound, "", "secret not found"), nil
	}
	return s.respWithSecretID(statusOK, sec.SecretID, ""), nil
}

func (s *Server) handleGet(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	root := msg.Root()
	token := root.Text(reqFieldToken)
	secretID := root.Text(reqFieldSecretID)

	claims, status, errMsg := s.authn(token)
	if status != statusOK {
		return s.respWithValue(status, nil, errMsg), nil
	}
	if secretID == "" {
		return s.respWithValue(statusBadRequest, nil, "secretId required"), nil
	}
	sec, err := s.secrets.GetByID(secretID)
	if err != nil {
		return s.respWithValue(statusNotFound, nil, "secret not found"), nil
	}
	if !canReadSecretFromAuth(claims, sec.TenantID) {
		return s.respWithValue(statusForbidden, nil, "forbidden"), nil
	}
	_ = s.audit.Append(sec.TenantID, map[string]any{
		"actor_id":     claims.Sub,
		"action":       "secret.read",
		"subject_id":   sec.SecretID,
		"subject_type": "secret",
		"transport":    "zap",
	})
	return s.respWithValue(statusOK, []byte(sec.Value), ""), nil
}

func (s *Server) handleCreate(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	root := msg.Root()
	token := root.Text(reqFieldToken)
	tenantID := root.Text(reqFieldTenantID)
	path := root.Text(reqFieldPath)
	name := root.Text(reqFieldName)
	value := root.Bytes(reqFieldValue)
	secretType := root.Text(reqFieldSecretType)

	claims, status, errMsg := s.authn(token)
	if status != statusOK {
		return s.respWithSecretID(status, "", errMsg), nil
	}
	if tenantID == "" || path == "" || name == "" || len(value) == 0 {
		return s.respWithSecretID(statusBadRequest, "", "tenantId, path, name, value required"), nil
	}
	if !isSecretAdminFromAuth(claims, tenantID) {
		return s.respWithSecretID(statusForbidden, "", "admin role required"), nil
	}
	sec := &store.ServiceSecret{
		OrgID:      tenantID,
		Path:       path,
		Name:       name,
		Value:      string(value),
		SecretType: secretType,
	}
	if err := s.secrets.Put(sec); err != nil {
		return s.respWithSecretID(statusServerError, "", "failed to store secret"), nil
	}
	_ = s.audit.Append(tenantID, map[string]any{
		"actor_id":     claims.Sub,
		"action":       "secret.create",
		"subject_id":   sec.SecretID,
		"subject_type": "secret",
		"transport":    "zap",
	})
	return s.respWithSecretID(statusOK, sec.SecretID, ""), nil
}

func (s *Server) handleUpdate(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	root := msg.Root()
	token := root.Text(reqFieldToken)
	secretID := root.Text(reqFieldSecretID)
	value := root.Bytes(reqFieldUpdValue)

	claims, status, errMsg := s.authn(token)
	if status != statusOK {
		return s.respStatusErr(status, errMsg), nil
	}
	if secretID == "" || len(value) == 0 {
		return s.respStatusErr(statusBadRequest, "secretId and value required"), nil
	}
	sec, err := s.secrets.GetByID(secretID)
	if err != nil {
		return s.respStatusErr(statusNotFound, "secret not found"), nil
	}
	if !isSecretAdminFromAuth(claims, sec.TenantID) {
		return s.respStatusErr(statusForbidden, "admin role required"), nil
	}
	if _, err := s.secrets.Update(secretID, string(value), nil); err != nil {
		return s.respStatusErr(statusServerError, "failed to update secret"), nil
	}
	_ = s.audit.Append(sec.TenantID, map[string]any{
		"actor_id":     claims.Sub,
		"action":       "secret.update",
		"subject_id":   secretID,
		"subject_type": "secret",
		"transport":    "zap",
	})
	return s.respStatusErr(statusOK, ""), nil
}

func (s *Server) handleDelete(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	root := msg.Root()
	token := root.Text(reqFieldToken)
	secretID := root.Text(reqFieldSecretID)

	claims, status, errMsg := s.authn(token)
	if status != statusOK {
		return s.respStatusErr(status, errMsg), nil
	}
	if secretID == "" {
		return s.respStatusErr(statusBadRequest, "secretId required"), nil
	}
	sec, err := s.secrets.GetByID(secretID)
	if err != nil {
		return s.respStatusErr(statusNotFound, "secret not found"), nil
	}
	if !isSecretAdminFromAuth(claims, sec.TenantID) {
		return s.respStatusErr(statusForbidden, "admin role required"), nil
	}
	if err := s.secrets.DeleteByID(secretID); err != nil {
		return s.respStatusErr(statusServerError, "failed to delete secret"), nil
	}
	_ = s.audit.Append(sec.TenantID, map[string]any{
		"actor_id":     claims.Sub,
		"action":       "secret.delete",
		"subject_id":   secretID,
		"subject_type": "secret",
		"transport":    "zap",
	})
	return s.respStatusErr(statusOK, ""), nil
}

// ── Auth ───────────────────────────────────────────────────────────────

// authn validates the IAM JWT carried in the request and returns claims
// or a status + error message. Mirrors auth.Middleware exactly: requires
// kid header, fetches matching public key from JWKS, enforces issuer +
// expiration, and refuses the legacy unsigned/empty-token paths.
func (s *Server) authn(tokenStr string) (*auth.Claims, uint32, string) {
	if tokenStr == "" {
		return nil, statusUnauthorized, "missing token"
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, statusUnauthorized, "malformed token"
	}
	kid, _ := unverified.Header["kid"].(string)
	if kid == "" {
		return nil, statusUnauthorized, "token missing kid"
	}
	pubKey, err := s.jwks.GetKey(kid)
	if err != nil {
		return nil, statusUnauthorized, "unknown signing key"
	}
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return pubKey, nil
	},
		jwt.WithIssuer(s.jwks.Issuer()),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return nil, statusUnauthorized, "invalid token"
	}
	mc, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, statusUnauthorized, "invalid claims"
	}
	c := &auth.Claims{
		Sub:   strClaim(mc, "sub"),
		Email: strClaim(mc, "email"),
		Owner: strClaim(mc, "owner"),
	}
	if rs, ok := mc["roles"].([]any); ok {
		for _, r := range rs {
			if rstr, ok := r.(string); ok {
				c.Roles = append(c.Roles, rstr)
			}
		}
	}
	return c, statusOK, ""
}

func strClaim(m jwt.MapClaims, key string) string {
	v, _ := m[key].(string)
	return v
}

// ── Authorization mirrors handler.helpers.go (canReadSecret / isSecretAdmin)
// without exporting those functions. We duplicate only what's needed here so
// the auth path is auditable in one file. Keep them in lockstep.

func hasRole(c *auth.Claims, role string) bool {
	if c == nil {
		return false
	}
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func isAdminFromAuth(c *auth.Claims) bool {
	return hasRole(c, "kms.admin")
}

func isSecretAdminFromAuth(c *auth.Claims, tenantID string) bool {
	if isAdminFromAuth(c) {
		return true
	}
	if c == nil || tenantID == "" || c.Owner != tenantID {
		return false
	}
	return hasRole(c, "kms.secret.admin")
}

func canReadSecretFromAuth(c *auth.Claims, tenantID string) bool {
	if isAdminFromAuth(c) {
		return true
	}
	if c == nil || c.Owner != tenantID {
		return false
	}
	return hasRole(c, "kms.secret.read") || hasRole(c, "kms.secret.admin")
}

// ── Response builders ───────────────────────────────────────────────────

func (s *Server) respWithSecretID(status uint32, secretID, errMsg string) *zap.Message {
	return s.build(func(o *zap.ObjectBuilder) {
		o.SetUint32(respFieldStatus, status)
		o.SetText(respFieldSecretID, secretID)
		o.SetText(respFieldError16, errMsg)
	}, 24)
}

func (s *Server) respWithValue(status uint32, value []byte, errMsg string) *zap.Message {
	return s.build(func(o *zap.ObjectBuilder) {
		o.SetUint32(respFieldStatus, status)
		o.SetBytes(respFieldValue, value)
		o.SetText(respFieldError16, errMsg)
	}, 24)
}

func (s *Server) respStatusErr(status uint32, errMsg string) *zap.Message {
	return s.build(func(o *zap.ObjectBuilder) {
		o.SetUint32(respFieldStatus, status)
		o.SetText(respFieldError8, errMsg)
	}, 16)
}

func (s *Server) build(setFields func(*zap.ObjectBuilder), dataSize int) *zap.Message {
	b := zap.NewBuilder(dataSize + 64)
	o := b.StartObject(dataSize)
	setFields(o)
	o.FinishAsRoot()
	data := b.Finish()
	msg, err := zap.Parse(data)
	if err != nil {
		// Should not happen — we just built it. Log and return a synthetic
		// 500 with an empty payload so the caller still gets something.
		s.logger.Error("zapsrv: build response failed", "error", err)
		fallback := zap.NewBuilder(64)
		fo := fallback.StartObject(16)
		fo.SetUint32(respFieldStatus, statusServerError)
		fo.SetText(respFieldError8, "response build failed")
		fo.FinishAsRoot()
		f, _ := zap.Parse(fallback.Finish())
		return f
	}
	return msg
}

// envOrDefault is a tiny helper exported only for tests that want to mirror
// the cmd/kmsd defaulting behavior without re-importing os.
func envOrDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
