package custody_test

// The contract between this library and whoever serves it.
//
// This repository holds keys and answers who signed a token; it derives no
// permission from one. The org-scoped HTTP plane and its authorization live in
// the cloud repo (apps/kms), the same place the secret plane moved to. So the
// mount below is not production code — it is the reference for that mount,
// written out in full because it is the thing the cloud side has to get right,
// and exercised here against the real client so the two halves cannot drift
// apart unnoticed.
//
// What the server owes custody, and what custody owes it:
//
//	the server  verifies the bearer, derives (org, subject, administrator) from
//	            it, and passes org and subject in. It never reads a tenant from
//	            the URL — the credential already answers that — and it refuses
//	            rebind and revoke to a caller without the administrator role.
//
//	custody     enforces everything that is a property of the key rather than a
//	            permission: the image the key opens under, the subject it belongs
//	            to, the epoch moving forward, the lifecycle. Those hold even if
//	            the mount above it is wrong.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hanzoai/kms/custody"
	"github.com/hanzoai/kms/sdk/go/kmsclient"
	"github.com/hanzoai/kms/sdk/go/node"
	badger "github.com/luxfi/zapdb"
)

const tenant = "hanzo"

// caller is what the serving side derives from a verified bearer. In cloud these
// come from the JWT's owner and sub claims plus the role check; here the mock IAM
// hands out an opaque token and the mount maps it back, because verifying a JWT
// is not this repository's job and pretending to do it would test the wrong
// thing.
type caller struct {
	org     string
	subject string
	admin   bool
}

// mount is the reference serving side. Everything it does is authorization and
// translation; every rule about the key itself is below it, in custody.
func mount(store *custody.Store, who func(*http.Request) (caller, bool)) http.Handler {
	mux := http.NewServeMux()

	// principal resolves the caller, or writes the refusal and reports false.
	principal := func(w http.ResponseWriter, r *http.Request) (caller, bool) {
		c, ok := who(r)
		if !ok {
			reply(w, http.StatusUnauthorized, map[string]any{"message": "unauthorized"})
		}
		return c, ok
	}
	// administrator additionally requires the role that rebinding and revoking
	// need: both assert what the fleet may run, not what one node claims.
	administrator := func(w http.ResponseWriter, r *http.Request) (caller, bool) {
		c, ok := principal(w, r)
		if !ok {
			return c, false
		}
		if !c.admin {
			reply(w, http.StatusForbidden, map[string]any{"message": "administrator role required"})
			return c, false
		}
		return c, true
	}
	// addressed parses the address the route names. A malformed one fails here,
	// in the decoder, and never reaches the store.
	addressed := func(w http.ResponseWriter, r *http.Request) (node.Address, bool) {
		address, err := node.ParseAddress(r.PathValue("address"))
		if err != nil {
			reply(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
			return address, false
		}
		return address, true
	}

	mux.HandleFunc("POST /v1/kms/nodes", func(w http.ResponseWriter, r *http.Request) {
		c, ok := principal(w, r)
		if !ok {
			return
		}
		var body struct {
			Evidence node.Evidence `json:"evidence"`
		}
		if !read(w, r, &body) {
			return
		}
		rec, created, err := store.Enroll(c.org, c.subject, body.Evidence)
		if err != nil {
			fail(w, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		reply(w, status, rec)
	})

	mux.HandleFunc("GET /v1/kms/nodes", func(w http.ResponseWriter, r *http.Request) {
		c, ok := principal(w, r)
		if !ok {
			return
		}
		fleet, err := store.List(c.org)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, fleet)
	})

	mux.HandleFunc("GET /v1/kms/nodes/{address}", func(w http.ResponseWriter, r *http.Request) {
		c, ok := principal(w, r)
		if !ok {
			return
		}
		address, ok := addressed(w, r)
		if !ok {
			return
		}
		rec, err := store.Get(c.org, address)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, rec)
	})

	mux.HandleFunc("POST /v1/kms/nodes/{address}/sign", func(w http.ResponseWriter, r *http.Request) {
		c, ok := principal(w, r)
		if !ok {
			return
		}
		address, ok := addressed(w, r)
		if !ok {
			return
		}
		var body struct {
			Evidence node.Evidence `json:"evidence"`
			Epoch    uint64        `json:"epoch"`
			Payload  []byte        `json:"payload"`
		}
		if !read(w, r, &body) {
			return
		}
		receipt, err := store.Sign(c.org, address, c.subject, body.Evidence, body.Epoch, body.Payload)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, receipt)
	})

	mux.HandleFunc("POST /v1/kms/nodes/{address}/rotate", func(w http.ResponseWriter, r *http.Request) {
		c, ok := principal(w, r)
		if !ok {
			return
		}
		address, ok := addressed(w, r)
		if !ok {
			return
		}
		var body struct {
			Evidence node.Evidence `json:"evidence"`
			Epoch    uint64        `json:"epoch"`
		}
		if !read(w, r, &body) {
			return
		}
		rec, handover, err := store.Rotate(c.org, address, c.subject, body.Evidence, body.Epoch)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusCreated, map[string]any{"node": rec, "succession": handover})
	})

	mux.HandleFunc("POST /v1/kms/nodes/{address}/rebind", func(w http.ResponseWriter, r *http.Request) {
		c, ok := administrator(w, r)
		if !ok {
			return
		}
		address, ok := addressed(w, r)
		if !ok {
			return
		}
		var body struct {
			From node.Evidence `json:"from"`
			To   node.Evidence `json:"to"`
		}
		if !read(w, r, &body) {
			return
		}
		rec, err := store.Rebind(c.org, address, body.From, body.To)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, rec)
	})

	mux.HandleFunc("POST /v1/kms/nodes/{address}/revoke", func(w http.ResponseWriter, r *http.Request) {
		c, ok := administrator(w, r)
		if !ok {
			return
		}
		address, ok := addressed(w, r)
		if !ok {
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if !read(w, r, &body) {
			return
		}
		rec, err := store.Revoke(c.org, address, body.Reason)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, rec)
	})

	return mux
}

// fail maps a custody error onto a status. The sentinels are safe to echo: each
// names a condition the caller can act on, and none carries key material or
// another tenant's state. Anything else says nothing beyond that it failed.
func fail(w http.ResponseWriter, err error) {
	status, message := http.StatusInternalServerError, "internal error"
	switch {
	case errors.Is(err, custody.ErrNotFound):
		status, message = http.StatusNotFound, err.Error()
	case errors.Is(err, custody.ErrSubject):
		status, message = http.StatusForbidden, err.Error()
	case errors.Is(err, custody.ErrDrift), errors.Is(err, custody.ErrNotActive), errors.Is(err, custody.ErrEpoch):
		status, message = http.StatusConflict, err.Error()
	case errors.Is(err, custody.ErrKeyDestroyed):
		status, message = http.StatusGone, err.Error()
	case errors.Is(err, custody.ErrMeasurement), errors.Is(err, custody.ErrQuoteNoTEE),
		errors.Is(err, custody.ErrNoVerifier), errors.Is(err, custody.ErrOrg):
		status, message = http.StatusBadRequest, err.Error()
	}
	reply(w, status, map[string]any{"message": message})
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// read decodes a body under a size cap. An absent body is allowed and leaves v
// zero: the field a route needs is validated below, so an empty request fails on
// the missing field rather than the missing envelope. A body of the wrong shape
// — including an address or measurement of the wrong width, which the protocol's
// own decoders refuse — is a 400 and never reaches the store.
func read(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		reply(w, http.StatusBadRequest, map[string]any{"message": "invalid request body"})
		return false
	}
	return true
}

// serving stands up the reference mount over a real store and returns a factory
// for clients bearing a given identity.
func serving(t *testing.T) func(subject string, admin bool) *kmsclient.Client {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions(filepath.Join(t.TempDir(), "kms")).WithLogger(nil))
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x7a
	}
	store, err := custody.New(db, key)
	if err != nil {
		t.Fatalf("custody.New: %v", err)
	}

	// The mount maps an opaque bearer back to the principal it was issued for.
	// In cloud this is JWT verification plus the org, sub and role claims.
	tokens := map[string]caller{}
	server := httptest.NewServer(mount(store, func(r *http.Request) (caller, bool) {
		c, ok := tokens[r.Header.Get("Authorization")]
		return c, ok
	}))
	t.Cleanup(server.Close)

	return func(subject string, admin bool) *kmsclient.Client {
		t.Helper()
		token := "Bearer " + subject
		tokens[token] = caller{org: tenant, subject: subject, admin: admin}

		iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": subject, "expires_in": 600,
			})
		}))
		t.Cleanup(iam.Close)

		c, err := kmsclient.New(kmsclient.Config{
			Endpoint: server.URL, IAMEndpoint: iam.URL,
			ClientID: subject, ClientSecret: "secret", Org: tenant,
		})
		if err != nil {
			t.Fatalf("kmsclient.New: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
}

func image(seed byte) node.Evidence {
	var m node.Measurement
	for i := range m {
		m[i] = seed
	}
	return node.Declare(m)
}

// The whole life of a node identity, driven the way the node daemon drives it.
func TestNodeLifecycleOverTheWire(t *testing.T) {
	client := serving(t)
	ctx := context.Background()
	daemon, operator := client("node-a", false), client("ops", true)
	boot := image(0x11)

	// Enrol. First boot mints the wallet; a restart returns the same one.
	rec, created, err := daemon.Enroll(ctx, boot)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !created || rec.Status != node.Active || rec.Attested {
		t.Fatalf("first enrolment: created=%v %+v", created, rec)
	}
	again, created, err := daemon.Enroll(ctx, boot)
	if err != nil || created || again.Address != rec.Address {
		t.Fatalf("restart re-enrolment: %s created=%v err=%v", again.Address, created, err)
	}

	// Attest a boot report, and verify it the way a verifier does: against the
	// payload the caller already holds.
	report := []byte("kernel+rootfs measurement report")
	receipt, err := daemon.Sign(ctx, rec.Address, boot, 1, report)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := receipt.Verify(report); err != nil {
		t.Fatalf("receipt does not verify: %v", err)
	}
	if receipt.Address != rec.Address || receipt.Measurement != boot.Measurement {
		t.Fatalf("receipt does not describe this node on this image: %+v", receipt)
	}
	if err := receipt.Verify([]byte("a report the node never signed")); err == nil {
		t.Fatal("the receipt verified against a payload that was never signed")
	}

	if got, err := daemon.Node(ctx, rec.Address); err != nil || got.Address != rec.Address {
		t.Fatalf("Node: %+v %v", got, err)
	}
	seen, err := daemon.Fleet(ctx)
	if err != nil || len(seen.Nodes) != 1 || seen.Truncated {
		t.Fatalf("Fleet: %+v %v", seen, err)
	}

	// Rotate. The handover is self-verifying and is what moves the stake.
	successor, handover, err := daemon.Rotate(ctx, rec.Address, boot, 2)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := handover.Verify(); err != nil {
		t.Fatalf("handover does not verify: %v", err)
	}
	if handover.Prev != rec.Address || handover.Next != successor.Address {
		t.Fatalf("handover names the wrong pair: %+v", handover)
	}

	// The retired identity stays a readable tombstone carrying what it signed,
	// so the chain can settle the handover after the key is gone.
	old, err := daemon.Node(ctx, rec.Address)
	if err != nil {
		t.Fatalf("read retired identity: %v", err)
	}
	if old.Status != node.Superseded || old.Succession == nil {
		t.Fatalf("retired identity is not a tombstone: %+v", old)
	}
	if err := old.Succession.Verify(); err != nil {
		t.Fatalf("recorded succession does not verify: %v", err)
	}

	// An image upgrade: administrative, and the key follows onto the new image.
	upgraded := image(0x22)
	moved, err := operator.Rebind(ctx, successor.Address, boot, upgraded)
	if err != nil {
		t.Fatalf("Rebind: %v", err)
	}
	if moved.Measurement != upgraded.Measurement || moved.Address != successor.Address {
		t.Fatalf("rebinding changed the wrong thing: %+v", moved)
	}
	after, err := daemon.Sign(ctx, successor.Address, upgraded, 3, report)
	if err != nil {
		t.Fatalf("Sign after rebinding: %v", err)
	}
	if err := after.Verify(report); err != nil || after.Measurement != upgraded.Measurement {
		t.Fatalf("receipt after rebinding: %+v %v", after, err)
	}

	// Decommission. The key is destroyed; the row survives so the address stays
	// attributable to whatever the chain settles against it.
	dead, err := operator.Revoke(ctx, successor.Address, "slashed: missing attestation")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if dead.Status != node.Revoked || dead.Reason == "" {
		t.Fatalf("revocation is not recorded: %+v", dead)
	}
	if _, err := daemon.Sign(ctx, successor.Address, upgraded, 4, report); err == nil {
		t.Fatal("a revoked identity signed")
	}
}

// Every refusal reaches the caller as a Failure carrying the status, so a daemon
// branches on the distinction rather than on message text.
func TestRefusalsCarryTheirStatusOverTheWire(t *testing.T) {
	client := serving(t)
	ctx := context.Background()
	daemon, sibling, operator := client("node-a", false), client("node-b", false), client("ops", true)
	boot := image(0x11)

	rec, _, err := daemon.Enroll(ctx, boot)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, err := daemon.Sign(ctx, rec.Address, boot, 5, []byte("x")); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for name, tc := range map[string]struct {
		call func() error
		want int
	}{
		"another image": {
			func() error { _, err := daemon.Sign(ctx, rec.Address, image(0x22), 6, []byte("x")); return err },
			http.StatusConflict,
		},
		"replayed epoch": {
			func() error { _, err := daemon.Sign(ctx, rec.Address, boot, 5, []byte("x")); return err },
			http.StatusConflict,
		},
		// The sibling holds a valid credential for the same tenant. Only the
		// subject binding stops it signing as its neighbour, and that binding is
		// custody's, not the mount's.
		"a sibling's identity": {
			func() error { _, err := sibling.Sign(ctx, rec.Address, boot, 6, []byte("x")); return err },
			http.StatusForbidden,
		},
		"rebinding without the role": {
			func() error { _, err := daemon.Rebind(ctx, rec.Address, boot, image(0x22)); return err },
			http.StatusForbidden,
		},
		"revoking without the role": {
			func() error { _, err := daemon.Revoke(ctx, rec.Address, "self"); return err },
			http.StatusForbidden,
		},
		"an unknown identity": {
			func() error { _, err := daemon.Node(ctx, node.Address{0x99}); return err },
			http.StatusNotFound,
		},
		"a malformed measurement": {
			func() error {
				_, _, err := sibling.Enroll(ctx, node.Evidence{TEE: node.None})
				return err
			},
			http.StatusBadRequest,
		},
		"an unbacked hardware claim": {
			func() error {
				_, _, err := sibling.Enroll(ctx, node.Evidence{
					TEE: node.SevSnp, Measurement: image(0x33).Measurement, Quote: []byte("report"),
				})
				return err
			},
			http.StatusBadRequest,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.call()
			var refusal *kmsclient.Failure
			if !errors.As(err, &refusal) {
				t.Fatalf("got %v, want a *kmsclient.Failure", err)
			}
			if refusal.Status != tc.want {
				t.Fatalf("status %d, want %d (%s)", refusal.Status, tc.want, refusal.Message)
			}
			if refusal.Message == "" {
				t.Fatal("the refusal carries no explanation")
			}
		})
	}

	// The operator's own operations still work, so the refusals above are about
	// authority rather than a surface that refuses everything.
	if _, err := operator.Rebind(ctx, rec.Address, boot, image(0x22)); err != nil {
		t.Fatalf("Rebind as an administrator: %v", err)
	}
}

// A caller with no credential reaches nothing, and key material never crosses
// the wire on any answer the surface gives.
func TestUnauthenticatedAndNoMaterialOnTheWire(t *testing.T) {
	client := serving(t)
	ctx := context.Background()
	daemon := client("node-a", false)
	boot := image(0x11)

	rec, _, err := daemon.Enroll(ctx, boot)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	receipt, err := daemon.Sign(ctx, rec.Address, boot, 1, []byte("report"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for name, body := range map[string]any{"record": rec, "receipt": receipt} {
		blob, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		for _, forbidden := range []string{"ciphertext", "wrapped_dek", "private"} {
			if bytes.Contains(bytes.ToLower(blob), []byte(forbidden)) {
				t.Fatalf("%s carries %q: %s", name, forbidden, blob)
			}
		}
	}

	// An unknown bearer is refused before anything is read.
	stranger, err := kmsclient.New(kmsclient.Config{
		Endpoint:    "http://127.0.0.1:1",
		IAMEndpoint: "http://127.0.0.1:1",
		ClientID:    "nobody", ClientSecret: "x", Org: tenant,
	})
	if err != nil {
		t.Fatalf("kmsclient.New: %v", err)
	}
	defer stranger.Close()
	if _, err := stranger.Fleet(ctx); err == nil {
		t.Fatal("a client with no reachable IAM returned a fleet")
	}
}
