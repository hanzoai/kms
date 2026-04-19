package zapsrv

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/luxfi/zap"

	"github.com/hanzoai/base"
	basecore "github.com/hanzoai/base/core"

	"github.com/hanzoai/kms/internal/auth"
	"github.com/hanzoai/kms/internal/store"
)

// ── Test fixtures ──────────────────────────────────────────────────────

type fixture struct {
	t       *testing.T
	app     basecore.App
	jwks    *auth.JWKSValidator
	signKey *rsa.PrivateKey
	server  *Server
	port    int
}

// newFixture stands up an in-memory Base app, a 1-key JWKS HTTP test
// server, and a ZAP secrets server bound to an ephemeral port.
func newFixture(t *testing.T) *fixture {
	t.Helper()

	// 1) Base app w/ all KMS collections bootstrapped.
	dir := t.TempDir()
	app := base.NewWithConfig(base.Config{DefaultDataDir: dir})

	// Bootstrap manually because we don't go through OnServe.
	if err := app.Bootstrap(); err != nil {
		t.Fatalf("base bootstrap: %v", err)
	}
	if err := store.Bootstrap(app); err != nil {
		t.Fatalf("kms bootstrap: %v", err)
	}

	// 2) RSA key + test JWKS endpoint.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nB := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		eB := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "alg": "RS256", "kid": "test-kid",
				"n": nB, "e": eB,
			}},
		})
	})
	jwksSrv := httptest.NewServer(jwksHandler)
	t.Cleanup(jwksSrv.Close)
	jwks := auth.NewJWKSValidator(jwksSrv.URL + "/.well-known/jwks.json")

	// 3) ZAP server on ephemeral port.
	port := freePort(t)
	srv, err := New(Config{
		NodeID:  fmt.Sprintf("test-%d", port),
		Port:    port,
		JWKS:    jwks,
		Secrets: store.NewServiceSecretStore(app),
		Audit:   store.NewAuditStore(app),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(srv.Stop)

	// 4) Wait for the listener to actually bind.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return &fixture{
		t: t, app: app, jwks: jwks, signKey: key,
		server: srv, port: port,
	}
}

// mintToken signs a JWT with the fixture key. Issuer matches the JWKS URL
// stripped of /.well-known/jwks.json so JWKSValidator.Issuer() agrees.
func (f *fixture) mintToken(sub, owner string, roles []string) string {
	f.t.Helper()
	claims := jwt.MapClaims{
		"iss":   f.jwks.Issuer(),
		"sub":   sub,
		"owner": owner,
		"roles": roles,
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-kid"
	signed, err := tok.SignedString(f.signKey)
	if err != nil {
		f.t.Fatalf("sign: %v", err)
	}
	return signed
}

// dial opens a fresh ZAP client connected to the test server. Each test gets
// its own client so connection state can't bleed across cases.
func (f *fixture) dial() (*zap.Node, string) {
	f.t.Helper()
	port := freePort(f.t)
	c := zap.NewNode(zap.NodeConfig{
		NodeID:      fmt.Sprintf("test-client-%d", port),
		ServiceType: "_kms-secrets-test._tcp",
		Port:        port,
		NoDiscovery: true,
	})
	if err := c.Start(); err != nil {
		f.t.Fatalf("client start: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", f.port)
	if err := c.ConnectDirect(addr); err != nil {
		c.Stop()
		f.t.Fatalf("connect: %v", err)
	}
	peers := c.Peers()
	if len(peers) == 0 {
		c.Stop()
		f.t.Fatalf("no peers after connect")
	}
	f.t.Cleanup(c.Stop)
	return c, peers[0]
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// callOpcode is the canonical request helper used by every test below.
func (f *fixture) callOpcode(opcode uint16, build func(*zap.ObjectBuilder), dataSize int) *zap.Message {
	f.t.Helper()
	c, peer := f.dial()
	b := zap.NewBuilder(dataSize + 256)
	o := b.StartObject(dataSize)
	build(o)
	o.FinishAsRoot()
	flags := uint16(opcode) << 8
	data := b.FinishWithFlags(flags)
	msg, err := zap.Parse(data)
	if err != nil {
		f.t.Fatalf("client parse: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Call(ctx, peer, msg)
	if err != nil {
		f.t.Fatalf("call: %v", err)
	}
	return resp
}

// ── Round-trip tests, one per opcode ───────────────────────────────────

func TestResolve_RoundTrip(t *testing.T) {
	f := newFixture(t)
	tok := f.mintToken("user-1", "tenant-x", []string{"kms.secret.admin"})

	// Pre-seed via the store so we have something to resolve.
	if err := f.server.secrets.Put(&store.ServiceSecret{
		OrgID: "tenant-x", Path: "providers/alpaca/dev", Name: "api_key",
		Value: "K1", SecretType: "api",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp := f.callOpcode(OpcodeSecretResolve, func(o *zap.ObjectBuilder) {
		o.SetText(reqFieldToken, tok)
		o.SetText(reqFieldTenantID, "tenant-x")
		o.SetText(reqFieldPath, "providers/alpaca/dev")
		o.SetText(reqFieldName, "api_key")
	}, 32)

	root := resp.Root()
	if got := root.Uint32(respFieldStatus); got != statusOK {
		t.Fatalf("status = %d, want %d (err=%q)", got, statusOK, root.Text(respFieldError16))
	}
	if root.Text(respFieldSecretID) == "" {
		t.Fatalf("empty secretId in resolve response")
	}
}

func TestGet_RoundTrip(t *testing.T) {
	f := newFixture(t)
	tok := f.mintToken("u", "tenant-y", []string{"kms.secret.read"})

	sec := &store.ServiceSecret{OrgID: "tenant-y", Path: "p", Name: "n", Value: "secret-value-42"}
	if err := f.server.secrets.Put(sec); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp := f.callOpcode(OpcodeSecretGet, func(o *zap.ObjectBuilder) {
		o.SetText(reqFieldToken, tok)
		o.SetText(reqFieldSecretID, sec.SecretID)
	}, 16)

	root := resp.Root()
	if got := root.Uint32(respFieldStatus); got != statusOK {
		t.Fatalf("status = %d, err=%q", got, root.Text(respFieldError16))
	}
	if v := root.Bytes(respFieldValue); !bytes.Equal(v, []byte("secret-value-42")) {
		t.Fatalf("value = %q", v)
	}
}

func TestCreate_RoundTrip(t *testing.T) {
	f := newFixture(t)
	tok := f.mintToken("u", "tenant-c", []string{"kms.secret.admin"})

	resp := f.callOpcode(OpcodeSecretCreate, func(o *zap.ObjectBuilder) {
		o.SetText(reqFieldToken, tok)
		o.SetText(reqFieldTenantID, "tenant-c")
		o.SetText(reqFieldPath, "p1")
		o.SetText(reqFieldName, "n1")
		o.SetBytes(reqFieldValue, []byte("create-value"))
		o.SetText(reqFieldSecretType, "api")
	}, 48)

	root := resp.Root()
	if got := root.Uint32(respFieldStatus); got != statusOK {
		t.Fatalf("status = %d, err=%q", got, root.Text(respFieldError16))
	}
	id := root.Text(respFieldSecretID)
	if id == "" {
		t.Fatalf("empty secretId")
	}

	// Verify via store.
	sec, err := f.server.secrets.GetByID(id)
	if err != nil {
		t.Fatalf("getByID: %v", err)
	}
	if sec.Value != "create-value" {
		t.Fatalf("stored value = %q", sec.Value)
	}
}

func TestUpdate_RoundTrip(t *testing.T) {
	f := newFixture(t)
	tok := f.mintToken("u", "tenant-u", []string{"kms.secret.admin"})

	sec := &store.ServiceSecret{OrgID: "tenant-u", Path: "p", Name: "n", Value: "v0"}
	if err := f.server.secrets.Put(sec); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp := f.callOpcode(OpcodeSecretUpdate, func(o *zap.ObjectBuilder) {
		o.SetText(reqFieldToken, tok)
		o.SetText(reqFieldSecretID, sec.SecretID)
		o.SetBytes(reqFieldUpdValue, []byte("v1-rotated"))
	}, 24)

	root := resp.Root()
	if got := root.Uint32(respFieldStatus); got != statusOK {
		t.Fatalf("status = %d, err=%q", got, root.Text(respFieldError8))
	}

	got, err := f.server.secrets.GetByID(sec.SecretID)
	if err != nil {
		t.Fatalf("getByID: %v", err)
	}
	if got.Value != "v1-rotated" {
		t.Fatalf("value after update = %q", got.Value)
	}
}

func TestDelete_RoundTrip(t *testing.T) {
	f := newFixture(t)
	tok := f.mintToken("u", "tenant-d", []string{"kms.secret.admin"})

	sec := &store.ServiceSecret{OrgID: "tenant-d", Path: "p", Name: "n", Value: "v"}
	if err := f.server.secrets.Put(sec); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp := f.callOpcode(OpcodeSecretDelete, func(o *zap.ObjectBuilder) {
		o.SetText(reqFieldToken, tok)
		o.SetText(reqFieldSecretID, sec.SecretID)
	}, 16)

	root := resp.Root()
	if got := root.Uint32(respFieldStatus); got != statusOK {
		t.Fatalf("status = %d, err=%q", got, root.Text(respFieldError8))
	}
	if _, err := f.server.secrets.GetByID(sec.SecretID); err == nil {
		t.Fatalf("expected secret deleted")
	}
}

// ── Auth + authorization regressions ───────────────────────────────────

func TestGet_RejectsMissingToken(t *testing.T) {
	f := newFixture(t)
	resp := f.callOpcode(OpcodeSecretGet, func(o *zap.ObjectBuilder) {
		o.SetText(reqFieldToken, "")
		o.SetText(reqFieldSecretID, "anything")
	}, 16)
	if got := resp.Root().Uint32(respFieldStatus); got != statusUnauthorized {
		t.Fatalf("status = %d, want %d", got, statusUnauthorized)
	}
}

func TestGet_RejectsCrossTenantRead(t *testing.T) {
	f := newFixture(t)
	if err := f.server.secrets.Put(&store.ServiceSecret{
		OrgID: "tenant-A", Path: "p", Name: "n", Value: "v",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := f.server.secrets.Get("tenant-A", "p", "n")
	if err != nil {
		t.Fatalf("seed read: %v", err)
	}

	// Caller belongs to tenant-B with secret.read role — must NOT read tenant-A.
	tok := f.mintToken("u", "tenant-B", []string{"kms.secret.read"})
	resp := f.callOpcode(OpcodeSecretGet, func(o *zap.ObjectBuilder) {
		o.SetText(reqFieldToken, tok)
		o.SetText(reqFieldSecretID, got.SecretID)
	}, 16)
	if status := resp.Root().Uint32(respFieldStatus); status != statusForbidden {
		t.Fatalf("cross-tenant read status = %d, want %d", status, statusForbidden)
	}
}

func TestCreate_RejectsReadOnlyRole(t *testing.T) {
	f := newFixture(t)
	tok := f.mintToken("u", "tenant-r", []string{"kms.secret.read"})
	resp := f.callOpcode(OpcodeSecretCreate, func(o *zap.ObjectBuilder) {
		o.SetText(reqFieldToken, tok)
		o.SetText(reqFieldTenantID, "tenant-r")
		o.SetText(reqFieldPath, "p")
		o.SetText(reqFieldName, "n")
		o.SetBytes(reqFieldValue, []byte("v"))
	}, 48)
	if got := resp.Root().Uint32(respFieldStatus); got != statusForbidden {
		t.Fatalf("status = %d, want %d", got, statusForbidden)
	}
}

func TestNew_RejectsMissingJWKS(t *testing.T) {
	_, err := New(Config{
		Secrets: &store.ServiceSecretStore{},
		Audit:   &store.AuditStore{},
	})
	if err == nil {
		t.Fatal("expected error when JWKS is nil")
	}
}

// ── Bench: ensure ZAP path stays well under the HTTP fallback (~1ms) ──

var benchSink atomic.Uint64

func BenchmarkGet_ZAP(b *testing.B) {
	t := &testing.T{}
	f := newFixture(t)
	tok := f.mintToken("u", "tenant-bench", []string{"kms.secret.read"})
	sec := &store.ServiceSecret{OrgID: "tenant-bench", Path: "p", Name: "n", Value: "v"}
	if err := f.server.secrets.Put(sec); err != nil {
		b.Fatalf("seed: %v", err)
	}
	c, peer := f.dial()
	defer c.Stop()

	// One pre-built request reused across iterations.
	build := func() *zap.Message {
		bld := zap.NewBuilder(256)
		o := bld.StartObject(16)
		o.SetText(reqFieldToken, tok)
		o.SetText(reqFieldSecretID, sec.SecretID)
		o.FinishAsRoot()
		flags := uint16(OpcodeSecretGet) << 8
		msg, _ := zap.Parse(bld.FinishWithFlags(flags))
		return msg
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := c.Call(ctx, peer, build())
		cancel()
		if err != nil {
			b.Fatalf("call: %v", err)
		}
		benchSink.Add(uint64(resp.Root().Uint32(respFieldStatus)))
	}
}
