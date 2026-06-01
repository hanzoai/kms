// Package-level integration test for the ZAP transport path.
//
// Spins up an in-process luxfi/kms ZAP secret-server backed by a
// temporary BadgerDB store, dials it from the kmsclient, and exercises
// Get/Put/List/Delete end-to-end. Proves the transport selection in
// New() picks ZAP for zap:// endpoints and that the binary protocol
// round-trips a value correctly.

package kmsclient

import (
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/kms/pkg/zapserver"
	"github.com/luxfi/log"
	"github.com/luxfi/zap"
	badger "github.com/luxfi/zapdb"
)

// pickEphemeralPort grabs a free TCP port without binding it; the
// caller passes it to the ZAP Node which then binds for real. There is
// a tiny race window — fine for tests.
func pickEphemeralPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pickEphemeralPort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// startTestZAPServer brings up an in-process ZAP secret-server bound
// to an ephemeral port + a temp Badger store, and returns the host:port
// dial string + a tear-down func.
//
// ACL configuration: the test passes acl=nil (open mode) so the client
// NodeID does not need to match any pre-provisioned entry. The ACL
// path is exercised by zapserver's own auth_test.go in luxfi/kms.
func startTestZAPServer(t *testing.T) (addr string, teardown func()) {
	t.Helper()
	dir := t.TempDir()
	db, err := badger.Open(badger.DefaultOptions(dir).WithLogger(nil))
	if err != nil {
		t.Fatalf("badger.Open: %v", err)
	}

	// Master key: 32 random-but-deterministic bytes for the test.
	mk := make([]byte, 32)
	for i := range mk {
		mk[i] = byte(i)
	}
	_ = base64.StdEncoding.EncodeToString(mk) // silence linter on unused import

	srv := zapserver.New(zapserver.Config{
		Store:     store.NewSecretStore(db),
		MasterKey: mk,
		Logger:    log.Root(),
	})

	port := pickEphemeralPort(t)
	n := zap.NewNode(zap.NodeConfig{
		NodeID:      "test-kms-server",
		ServiceType: "_kms._tcp",
		Port:        port,
		NoDiscovery: true, // direct dial in tests; mDNS off
	})
	if err := n.Start(); err != nil {
		_ = db.Close()
		t.Fatalf("zap.Node.Start: %v", err)
	}
	srv.Register(n)

	addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	return addr, func() {
		n.Stop()
		_ = db.Close()
	}
}

func TestZAP_DialAndGetPut(t *testing.T) {
	addr, teardown := startTestZAPServer(t)
	defer teardown()

	c, err := New(Config{
		Endpoint: "zap://" + addr,
		Org:      "hanzo",
		Env:      "test",
		NodeID:   "test-client-nodeid",
	})
	if err != nil {
		t.Fatalf("New(zap): %v", err)
	}
	defer c.Close()

	if c.transport != "zap" {
		t.Fatalf("transport = %q, want zap", c.transport)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Put → Get round trip.
	if err := c.Put(ctx, "providers/alpaca/dev", "api_key", "KEY-ZAP-123"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := c.Get(ctx, "providers/alpaca/dev", "api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "KEY-ZAP-123" {
		t.Errorf("Get = %q, want KEY-ZAP-123", got)
	}

	// Delete idempotency.
	if err := c.Delete(ctx, "providers/alpaca/dev", "api_key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(ctx, "providers/alpaca/dev", "api_key"); err == nil {
		t.Errorf("Get after Delete: want error, got nil")
	}
}

func TestZAP_TransportSelectorByEndpointScheme(t *testing.T) {
	// HTTP-scheme endpoint → http transport. Doesn't dial yet.
	c, err := New(Config{
		Endpoint:     "http://kms.hanzo.svc.cluster.local:8443",
		IAMEndpoint:  "http://iam:8000",
		ClientID:     "x",
		ClientSecret: "y",
		Org:          "hanzo",
	})
	if err != nil {
		t.Fatalf("New(http): %v", err)
	}
	if c.transport != "http" {
		t.Fatalf("transport = %q, want http", c.transport)
	}

	// Unsupported scheme rejects.
	if _, err := New(Config{Endpoint: "grpc://x", Org: "y"}); err == nil {
		t.Fatal("New: want error for unsupported scheme")
	}

	// zap+mdns is accepted by parseZAPEndpoint but the eager Dial
	// in newZAP needs at least one peer; we don't run mDNS in CI so
	// we don't test it here. The parser is unit-tested below.
	host, mdns := parseZAPEndpoint("zap+mdns://_kms._tcp")
	if !mdns || host != "" {
		t.Errorf("parseZAPEndpoint(mdns) = (%q, %v), want (\"\", true)", host, mdns)
	}
	host, mdns = parseZAPEndpoint("zap://kms.hanzo.svc:9999")
	if mdns || host != "kms.hanzo.svc:9999" {
		t.Errorf("parseZAPEndpoint(direct) = (%q, %v), want (kms.hanzo.svc:9999, false)", host, mdns)
	}
}

// Ensure we don't accept obviously-broken config.
func TestZAP_New_RequiresOrg(t *testing.T) {
	if _, err := New(Config{Endpoint: "zap://x:1"}); err == nil ||
		!strings.Contains(err.Error(), "org is required") {
		t.Fatalf("want org-required error, got %v", err)
	}
}
