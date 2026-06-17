// Package zapclient is the native ZAP-transport counterpart to pkg/zapserver.
//
// Services wanting to fetch secrets from KMS without a REST round-trip
// spin up a short-lived ZAP Node (mDNS-discovered or direct-addressed) and
// call the four opcodes defined in zapserver:
//
//	0x0040  OpSecretGet    { path, name, env }            → { value }
//	0x0041  OpSecretPut    { path, name, env, value }     → { ok:true }   (admin)
//	0x0042  OpSecretList   { path, env }                  → { names }
//	0x0043  OpSecretDelete { path, name, env }            → { ok:true }   (admin)
//
// Example:
//
//	c, _ := zapclient.Dial(ctx, "kms:9652", "secret/data/onyxplus/dev")
//	defer c.Close()
//	v, _ := c.Get(ctx, "SIGNING_KEY_PEM", "dev")
//
// This is the preferred path for in-cluster consumers. REST via pkg/client
// remains available for external / cross-cluster callers.
package zapclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/luxfi/kms/pkg/envelope"
	kmszap "github.com/luxfi/kms/pkg/zap"
	"github.com/luxfi/zap"
)

// Opcodes mirror the server; kept verbatim to avoid drift.
const (
	OpSecretGet    uint16 = 0x0040
	OpSecretPut    uint16 = 0x0041
	OpSecretList   uint16 = 0x0042
	OpSecretDelete uint16 = 0x0043
)

const (
	statusOK       byte = 0x00
	statusNotFound byte = 0x01
	statusError    byte = 0x02
	statusForbid   byte = 0x03
)

// ErrNotFound is returned when a secret path/name does not exist.
var ErrNotFound = errors.New("zapclient: secret not found")

// ErrForbidden is returned when the caller lacks role=admin for Put/Delete.
var ErrForbidden = errors.New("zapclient: forbidden (admin role required)")

// Client is a thin wrapper over a zap.Node plus a resolved KMS peer ID.
type Client struct {
	node        *zap.Node
	peerID      string
	defaultPath string
	log         *slog.Logger

	// Hybrid handshake session. Populated by handshake() after Dial.
	// nil means handshake skipped (peer didn't speak the new opcode set
	// or LocalCaps disabled the bit) — request bodies remain plaintext.
	session *kmszap.Session
	// Capability bitmap the client offers in ClientHello. Defaults to
	// CapMLKEM768 in DialWithConfig; set to 0 in Config.LocalCaps to
	// force a classical-only path for testing the fallback.
	localCaps uint16

	// Envelope identity: the consensus-native auth carrier. Every
	// secret-opcode call signs an envelope (op, request, ts, nonce)
	// with this signer; the server verifies + authorizes via consensus.
	//
	// identityHeader is the public block embedded in every envelope.
	// signer is the ML-DSA-65 private-key holder.
	identityHeader envelope.IdentityHeader
	signer         envelope.Signer
}

// Config controls client construction.
type Config struct {
	// NodeID we present to the mesh. Defaults to "kmsclient-<random>".
	NodeID string
	// Port to listen on (0 = OS-assigned). ZAP requires a listener even for callers.
	Port int
	// PeerAddr (host:port) of the KMS node. If non-empty, Dial uses
	// ConnectDirect. If empty, Dial uses mDNS discovery by ServiceType.
	PeerAddr string
	// ServiceType for mDNS discovery. Defaults to "_kms._tcp".
	ServiceType string
	// DefaultPath prefixes all calls that omit an explicit path.
	DefaultPath string
	// Logger (optional).
	Logger *slog.Logger
	// LocalCaps overrides the capability bitmap the client advertises in
	// ClientHello. Zero value means "use the default" (CapMLKEM768).
	// Set to a non-zero value WITHOUT bit 0 to force classical-only.
	LocalCaps uint16
	// CapsExplicit, when true, means LocalCaps was set deliberately and
	// the zero-value default should not be applied. Use to send caps=0.
	CapsExplicit bool
	// SkipHandshake disables the application-layer hybrid handshake
	// entirely. Reserved for talking to legacy peers that don't speak
	// OpClientHello. The connection then falls back to plaintext payloads.
	SkipHandshake bool

	// IdentityHeader is the public block embedded in every envelope.
	// Required for the secret-opcode surface; absent → the wire path
	// fails fast at first request. Build it via
	// envelope.HeaderFromServiceIdentity(*keys.ServiceIdentity).
	IdentityHeader envelope.IdentityHeader
	// Signer signs every outbound envelope's canonical digest.
	// Required for the secret-opcode surface (same as IdentityHeader).
	// *keys.ServiceIdentity satisfies envelope.Signer directly.
	Signer envelope.Signer
}

// Dial brings up a ZAP node, connects to the KMS peer, and returns a ready
// client. Close when done.
func Dial(ctx context.Context, peerAddr, defaultPath string) (*Client, error) {
	return DialWithConfig(ctx, Config{PeerAddr: peerAddr, DefaultPath: defaultPath})
}

// DialWithConfig is the full-options form.
func DialWithConfig(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.NodeID == "" {
		cfg.NodeID = "kmsclient"
	}
	if cfg.ServiceType == "" {
		cfg.ServiceType = "_kms._tcp"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Direct-address callers don't need mDNS and shouldn't advertise
	// themselves on the network. Only request discovery when the caller
	// explicitly leaves PeerAddr empty.
	n := zap.NewNode(zap.NodeConfig{
		NodeID:      cfg.NodeID,
		ServiceType: cfg.ServiceType,
		Port:        cfg.Port,
		NoDiscovery: cfg.PeerAddr != "",
	})
	if err := n.Start(); err != nil {
		return nil, fmt.Errorf("zapclient: start node: %w", err)
	}

	caps := cfg.LocalCaps
	if !cfg.CapsExplicit {
		caps = kmszap.CapMLKEM768
	}
	c := &Client{
		node:           n,
		defaultPath:    cfg.DefaultPath,
		log:            cfg.Logger,
		localCaps:      caps,
		identityHeader: cfg.IdentityHeader,
		signer:         cfg.Signer,
	}

	if cfg.PeerAddr != "" {
		if err := n.ConnectDirect(cfg.PeerAddr); err != nil {
			n.Stop()
			return nil, fmt.Errorf("zapclient: connect %s: %w", cfg.PeerAddr, err)
		}
		// ConnectDirect registers the peer under its advertised NodeID; we
		// pick the first peer we see as our target.
		for _, pid := range n.Peers() {
			c.peerID = pid
			break
		}
	} else {
		// mDNS discovery. Wait briefly for a peer to show up.
		timeout, cancel := context.WithCancel(ctx)
		defer cancel()
		for {
			peers := n.Peers()
			if len(peers) > 0 {
				c.peerID = peers[0]
				break
			}
			select {
			case <-timeout.Done():
				n.Stop()
				return nil, fmt.Errorf("zapclient: no KMS peer discovered")
			default:
			}
		}
	}

	if c.peerID == "" {
		n.Stop()
		return nil, fmt.Errorf("zapclient: peer not resolved")
	}

	// Application-layer hybrid handshake. Per LP-022, every ZAP
	// connection runs an X25519 + ML-KEM-768 hybrid key agreement
	// before any secret opcode flows. A peer that doesn't speak
	// OpClientHello returns a ZAP error and we fall back to plaintext.
	if !cfg.SkipHandshake {
		if err := c.handshake(ctx); err != nil {
			c.log.Warn("zapclient: handshake skipped — proceeding plaintext",
				"peer", c.peerID, "err", err)
			// Forward-compat: don't tear down the client; some legacy
			// peers may not speak OpClientHello yet. The connection still
			// works for opcodes that don't expect AEAD-sealed bodies.
			c.session = nil
		}
	}
	return c, nil
}

// handshake runs the client side of the hybrid PQ handshake against the
// resolved peer and stores the derived session on the client. A non-nil
// error means the peer rejected or could not complete; the caller may
// log and proceed in classical-only/plaintext mode.
func (c *Client) handshake(ctx context.Context) error {
	state, helloWire, err := kmszap.NewClient(c.localCaps)
	if err != nil {
		return fmt.Errorf("zapclient: build ClientHello: %w", err)
	}
	// ClientHello rides as op=OpClientHello with payload=helloWire.
	reqPayload := make([]byte, 2+len(helloWire))
	binary.LittleEndian.PutUint16(reqPayload[:2], kmszap.OpClientHello)
	copy(reqPayload[2:], helloWire)
	reqMsg := buildMessageWithType(kmszap.OpClientHello, reqPayload)
	if reqMsg == nil {
		return errors.New("zapclient: failed to build ClientHello message")
	}
	resp, err := c.node.Call(ctx, c.peerID, reqMsg)
	if err != nil {
		return fmt.Errorf("zapclient: handshake call: %w", err)
	}
	root := resp.Root()
	raw := root.Bytes(0)
	if len(raw) < 1 {
		b := resp.Bytes()
		if len(b) <= zap.HeaderSize {
			return io.ErrUnexpectedEOF
		}
		raw = b[zap.HeaderSize:]
	}
	if len(raw) < 1 {
		return io.ErrUnexpectedEOF
	}
	if raw[0] != statusOK {
		return fmt.Errorf("zapclient: handshake rejected: status=0x%02X body=%s", raw[0], string(raw[1:]))
	}
	result, err := state.ClientFinish(raw[1:])
	if err != nil {
		return fmt.Errorf("zapclient: ClientFinish: %w", err)
	}
	sess, err := kmszap.NewSession(result.SessionKey, result.Hybrid)
	if err != nil {
		return fmt.Errorf("zapclient: session init: %w", err)
	}
	c.session = sess
	if !result.Hybrid {
		c.log.Warn("zapclient: handshake classical-only — peer cleared ML-KEM-768 cap bit",
			"peer", c.peerID, "peerCaps", result.PeerCaps)
	} else {
		c.log.Info("zapclient: handshake hybrid", "peer", c.peerID, "alg", "X25519+ML-KEM-768")
	}
	return nil
}

// Close tears down the underlying ZAP node.
func (c *Client) Close() { c.node.Stop() }

// Get reads a secret. `path` falls back to DefaultPath if empty.
func (c *Client) Get(ctx context.Context, name, env string) (string, error) {
	return c.GetAt(ctx, c.defaultPath, name, env)
}

// GetAt reads a secret at an explicit path.
func (c *Client) GetAt(ctx context.Context, path, name, env string) (string, error) {
	body, _ := json.Marshal(map[string]string{"path": path, "name": name, "env": env})
	resp, err := c.call(ctx, OpSecretGet, body)
	if err != nil {
		return "", err
	}
	var out struct{ Value string }
	if err := json.Unmarshal(resp, &out); err != nil {
		return "", fmt.Errorf("zapclient: decode Get: %w", err)
	}
	b, err := base64.StdEncoding.DecodeString(out.Value)
	if err != nil {
		return "", fmt.Errorf("zapclient: decode value: %w", err)
	}
	return string(b), nil
}

// Put writes a secret. Requires admin role on the caller principal.
func (c *Client) Put(ctx context.Context, name, env, value string) error {
	return c.PutAt(ctx, c.defaultPath, name, env, value)
}

// PutAt writes a secret at an explicit path.
func (c *Client) PutAt(ctx context.Context, path, name, env, value string) error {
	body, _ := json.Marshal(map[string]string{
		"path":  path,
		"name":  name,
		"env":   env,
		"value": base64.StdEncoding.EncodeToString([]byte(value)),
	})
	_, err := c.call(ctx, OpSecretPut, body)
	return err
}

// List names at a path.
func (c *Client) List(ctx context.Context, env string) ([]string, error) {
	return c.ListAt(ctx, c.defaultPath, env)
}

// ListAt names at an explicit path.
func (c *Client) ListAt(ctx context.Context, path, env string) ([]string, error) {
	body, _ := json.Marshal(map[string]string{"path": path, "env": env})
	resp, err := c.call(ctx, OpSecretList, body)
	if err != nil {
		return nil, err
	}
	var out struct{ Names []string }
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("zapclient: decode List: %w", err)
	}
	return out.Names, nil
}

// Delete removes a secret. Admin-only.
func (c *Client) Delete(ctx context.Context, name, env string) error {
	return c.DeleteAt(ctx, c.defaultPath, name, env)
}

// DeleteAt removes a secret at an explicit path. Admin-only.
func (c *Client) DeleteAt(ctx context.Context, path, name, env string) error {
	body, _ := json.Marshal(map[string]string{"path": path, "name": name, "env": env})
	_, err := c.call(ctx, OpSecretDelete, body)
	return err
}

// call is the shared request/response wrapper around zap.Node.Call.
//
// Wire format on both directions: opcode(2 LE) || envelope-json for
// the request, status(1 byte) || json for the response, all packed in
// a ZAP Message via the Builder. When the client has a hybrid session,
// the envelope is sealed before the opcode prefix is added and the
// response payload is opened on receipt.
//
// Envelope construction binds the request body, opcode, timestamp,
// and a fresh per-call nonce into an ML-DSA-65 signature the server
// verifies before authorization runs. Without an identity wired in
// Config the wire path fails fast.
func (c *Client) call(ctx context.Context, op uint16, body []byte) ([]byte, error) {
	if c.signer == nil || len(c.identityHeader.PublicKey) == 0 {
		return nil, errors.New("zapclient: no identity wired (Config.IdentityHeader + Signer)")
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("zapclient: nonce: %w", err)
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	env, err := envelope.Build(c.identityHeader, c.signer, op, body, nonce, time.Now())
	if err != nil {
		return nil, fmt.Errorf("zapclient: envelope: %w", err)
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("zapclient: marshal envelope: %w", err)
	}
	wireBody := envBytes
	if c.session != nil {
		sealed, err := c.session.Seal(kmszap.DirClientToServer, envBytes)
		if err != nil {
			return nil, fmt.Errorf("zapclient: seal: %w", err)
		}
		wireBody = sealed
	}
	// Request: opcode in flags field (handler dispatch) + body in payload.
	// Body still carries the op prefix for the universal handler fallback.
	reqPayload := make([]byte, 2+len(wireBody))
	binary.LittleEndian.PutUint16(reqPayload[:2], op)
	copy(reqPayload[2:], wireBody)
	reqMsg := buildMessageWithType(op, reqPayload)
	if reqMsg == nil {
		return nil, errors.New("zapclient: failed to build request message")
	}

	resp, err := c.node.Call(ctx, c.peerID, reqMsg)
	if err != nil {
		return nil, fmt.Errorf("zapclient: call: %w", err)
	}
	// Response body: the zapserver builds it via Builder.WriteBytes({status || json}).
	// Try Root().Bytes(0) first (when the server wraps in an Object). Fall back
	// to msg.Bytes()[HeaderSize:] which strips the 16-byte ZAP frame header.
	root := resp.Root()
	raw := root.Bytes(0)
	if len(raw) < 1 {
		b := resp.Bytes()
		if len(b) <= zap.HeaderSize {
			return nil, io.ErrUnexpectedEOF
		}
		raw = b[zap.HeaderSize:]
	}
	if len(raw) < 1 {
		return nil, io.ErrUnexpectedEOF
	}
	status, payload := raw[0], raw[1:]
	if c.session != nil {
		pt, err := c.session.Open(kmszap.DirServerToClient, payload)
		if err != nil {
			return nil, fmt.Errorf("zapclient: open: %w", err)
		}
		payload = pt
	}
	switch status {
	case statusOK:
		return payload, nil
	case statusNotFound:
		return nil, ErrNotFound
	case statusForbid:
		return nil, ErrForbidden
	default:
		return nil, fmt.Errorf("zapclient: server error: %s", string(payload))
	}
}

// buildMessageWithType packs bytes into a parseable ZAP Message with the
// message type set in the flags field so the Node dispatches to the correct
// per-opcode handler (msgType = flags >> 8).
func buildMessageWithType(op uint16, body []byte) *zap.Message {
	b := zap.NewBuilder(len(body) + 32)
	b.WriteBytes(body)
	raw := b.FinishWithFlags(op << 8)
	msg, err := zap.Parse(raw)
	if err != nil {
		return nil
	}
	return msg
}
