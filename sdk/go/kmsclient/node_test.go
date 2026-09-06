package kmsclient

// Unit tests for the node custody calls. What the client and the server must
// agree on end to end is covered by the contract test in the server repo, which
// runs this client against the real surface; these cover the parts that test
// cannot reach — the transport refusal, the body cap, and the exact request each
// call puts on the wire.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/kms/sdk/go/node"
)

const bearer = "node-bearer"

func measurement(seed byte) node.Measurement {
	var m node.Measurement
	for i := range m {
		m[i] = seed
	}
	return m
}

func address(seed byte) node.Address {
	var a node.Address
	for i := range a {
		a[i] = seed
	}
	return a
}

// recorder keeps the request and body the handler saw, and the answer it should
// give back.
type recorder struct {
	req    *http.Request
	body   []byte
	status int
	answer any
}

func serve(t *testing.T, rec *recorder) *Client {
	t.Helper()
	iam := mockIAM(t, bearer)
	t.Cleanup(iam.Close)

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.body, _ = io.ReadAll(r.Body)
		rec.req = r
		w.Header().Set("Content-Type", "application/json")
		if rec.status != 0 {
			w.WriteHeader(rec.status)
		}
		if rec.answer != nil {
			_ = json.NewEncoder(w).Encode(rec.answer)
		}
	}))
	t.Cleanup(kms.Close)

	c, err := New(Config{
		Endpoint: kms.URL, IAMEndpoint: iam.URL,
		ClientID: "node", ClientSecret: "secret", Org: "hanzo",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// Each call goes to exactly one documented path, with the bearer attached and
// the body the surface expects. A rename on either side shows up here.
func TestNodeCallsUseTheCanonicalPaths(t *testing.T) {
	addr := address(0xab)
	ev := node.Declare(measurement(0x11))
	// No tenant in the path: the server takes the org from the credential, the
	// way the secret surface does.
	const base = "/v1/kms/nodes"

	for name, tc := range map[string]struct {
		call   func(*Client) error
		method string
		path   string
		status int
		answer any
		body   map[string]any
	}{
		"enroll": {
			func(c *Client) error { _, _, err := c.Enroll(context.Background(), ev); return err },
			http.MethodPost, base, http.StatusCreated, node.Record{Address: addr},
			map[string]any{"evidence": map[string]any{"tee": "none", "measurement": ev.Measurement.String()}},
		},
		"fleet": {
			func(c *Client) error { _, err := c.Fleet(context.Background()); return err },
			http.MethodGet, base, http.StatusOK, node.Fleet{}, nil,
		},
		"read": {
			func(c *Client) error { _, err := c.Node(context.Background(), addr); return err },
			http.MethodGet, base + "/" + addr.String(), http.StatusOK, node.Record{Address: addr}, nil,
		},
		"sign": {
			func(c *Client) error {
				_, err := c.Sign(context.Background(), addr, ev, 7, []byte("report"))
				return err
			},
			http.MethodPost, base + "/" + addr.String() + "/sign", http.StatusOK, node.Receipt{},
			map[string]any{"epoch": float64(7), "payload": "cmVwb3J0"},
		},
		"rotate": {
			func(c *Client) error { _, _, err := c.Rotate(context.Background(), addr, ev, 8); return err },
			http.MethodPost, base + "/" + addr.String() + "/rotate", http.StatusCreated,
			map[string]any{}, map[string]any{"epoch": float64(8)},
		},
		"rebind": {
			func(c *Client) error {
				_, err := c.Rebind(context.Background(), addr, ev, node.Declare(measurement(0x22)))
				return err
			},
			http.MethodPost, base + "/" + addr.String() + "/rebind", http.StatusOK, node.Record{},
			map[string]any{
				"from": map[string]any{"tee": "none", "measurement": measurement(0x11).String()},
				"to":   map[string]any{"tee": "none", "measurement": measurement(0x22).String()},
			},
		},
		"revoke": {
			func(c *Client) error { _, err := c.Revoke(context.Background(), addr, "slashed"); return err },
			http.MethodPost, base + "/" + addr.String() + "/revoke", http.StatusOK, node.Record{},
			map[string]any{"reason": "slashed"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{status: tc.status, answer: tc.answer}
			c := serve(t, rec)
			if err := tc.call(c); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if rec.req.Method != tc.method || rec.req.URL.Path != tc.path {
				t.Fatalf("%s %s, want %s %s", rec.req.Method, rec.req.URL.Path, tc.method, tc.path)
			}
			if got := rec.req.Header.Get("Authorization"); got != "Bearer "+bearer {
				t.Fatalf("authorization %q", got)
			}
			// No path segment is ever "/api/", and the address is spelled one way.
			if strings.Contains(rec.req.URL.Path, "/api/") {
				t.Fatalf("path carries an /api/ segment: %s", rec.req.URL.Path)
			}
			for k, want := range tc.body {
				var body map[string]any
				if err := json.Unmarshal(rec.body, &body); err != nil {
					t.Fatalf("request body: %v (%s)", err, rec.body)
				}
				got, ok := body[k]
				if !ok {
					t.Fatalf("request body has no %q: %s", k, rec.body)
				}
				if wantMap, isMap := want.(map[string]any); isMap {
					gotJSON, _ := json.Marshal(got)
					wantJSON, _ := json.Marshal(wantMap)
					if string(gotJSON) != string(wantJSON) {
						t.Fatalf("%q is %s, want %s", k, gotJSON, wantJSON)
					}
					continue
				}
				if got != want {
					t.Fatalf("%q is %v, want %v", k, got, want)
				}
			}
		})
	}
}

// Enrolment reports which of the two things happened, because a daemon has to
// tell a first boot from a restart.
func TestEnrollReportsWhetherItMinted(t *testing.T) {
	for status, want := range map[int]bool{http.StatusCreated: true, http.StatusOK: false} {
		rec := &recorder{status: status, answer: node.Record{Address: address(0xab)}}
		c := serve(t, rec)
		_, created, err := c.Enroll(context.Background(), node.Declare(measurement(0x11)))
		if err != nil {
			t.Fatalf("Enroll: %v", err)
		}
		if created != want {
			t.Fatalf("status %d reported created=%v, want %v", status, created, want)
		}
	}
}

// A refusal reaches the caller as a Failure carrying the status the surface
// chose, so a daemon branches on that rather than on message text.
func TestRefusalsCarryStatusAndMessage(t *testing.T) {
	rec := &recorder{status: http.StatusConflict, answer: map[string]any{
		"message": "custody: measurement differs from the one this identity is sealed to",
	}}
	c := serve(t, rec)

	_, err := c.Sign(context.Background(), address(0xab), node.Declare(measurement(0x11)), 1, nil)
	var refusal *Failure
	if !errors.As(err, &refusal) {
		t.Fatalf("got %v, want a *Failure", err)
	}
	if refusal.Status != http.StatusConflict || !strings.Contains(refusal.Message, "measurement differs") {
		t.Fatalf("refusal does not carry the surface's answer: %+v", refusal)
	}
	if !strings.Contains(refusal.Error(), "409") {
		t.Fatalf("Error() hides the status: %s", refusal.Error())
	}
}

// A refusal whose body is not the documented shape still reaches the caller
// intact rather than as an empty message.
func TestRefusalFallsBackToTheRawBody(t *testing.T) {
	rec := &recorder{status: http.StatusBadGateway, answer: "upstream exploded"}
	c := serve(t, rec)

	_, err := c.Fleet(context.Background())
	var refusal *Failure
	if !errors.As(err, &refusal) || !strings.Contains(refusal.Message, "upstream exploded") {
		t.Fatalf("got %v, want the raw body in the message", err)
	}
}

// The daemon reaches the KMS over the network before it has joined anything, so
// a body it cannot bound is a body that can exhaust it.
func TestResponsesAreBounded(t *testing.T) {
	iam := mockIAM(t, bearer)
	defer iam.Close()

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"nodes":[`))
		chunk := strings.Repeat(`{"org":"hanzo"},`, 1024)
		for written := 0; written < 4*maxResponse; written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer kms.Close()

	c, err := New(Config{
		Endpoint: kms.URL, IAMEndpoint: iam.URL,
		ClientID: "node", ClientSecret: "secret", Org: "hanzo",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	// The read stops at the cap, so the truncated JSON fails to decode rather
	// than growing without bound.
	if _, err := c.Fleet(context.Background()); err == nil {
		t.Fatal("an unbounded response was accepted")
	}
}

// Node custody is HTTP only: a node asks for its identity before it has joined
// the cluster, so the in-cluster transport is refused here rather than left to
// fail somewhere less obvious.
func TestNodeCallsRefuseTheClusterTransport(t *testing.T) {
	c := &Client{transport: "zap", org: "hanzo"}
	ctx := context.Background()
	addr := address(0xab)
	ev := node.Declare(measurement(0x11))

	for name, call := range map[string]func() error{
		"enroll": func() error { _, _, err := c.Enroll(ctx, ev); return err },
		"fleet":  func() error { _, err := c.Fleet(ctx); return err },
		"read":   func() error { _, err := c.Node(ctx, addr); return err },
		"sign":   func() error { _, err := c.Sign(ctx, addr, ev, 1, nil); return err },
		"rotate": func() error { _, _, err := c.Rotate(ctx, addr, ev, 1); return err },
		"rebind": func() error { _, err := c.Rebind(ctx, addr, ev, ev); return err },
		"revoke": func() error { _, err := c.Revoke(ctx, addr, "x"); return err },
	} {
		if err := call(); !errors.Is(err, ErrTransport) {
			t.Fatalf("%s over ZAP: got %v, want ErrTransport", name, err)
		}
	}
}
