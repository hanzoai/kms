// Package zapserver exposes the KMS Secret store over luxfi/zap.
//
// Wire format per request: opcode(2 LE) || envelope JSON.
// Response: 1-byte status (0x00 ok, 0x01 not found, 0x02 error,
// 0x03 forbid) || payload.
//
// Opcodes:
//
//	0x0040  OpSecretGet   { path, name, env }          → { value: base64 } or not-found
//	0x0041  OpSecretPut   { path, name, env, value }   → { ok: true }           (admin only)
//	0x0042  OpSecretList  { path, env }                → { names: []string }
//	0x0043  OpSecretDelete{ path, name, env }          → { ok: true }           (admin only)
//
// Auth: every secret-opcode payload is wrapped in a signed Envelope
// (see auth.go). The envelope carries the caller's mnemonic-derived
// service NodeID (ML-DSA-65 scheme), a 48-byte SHAKE256-384 commitment
// to the identity, and an ML-DSA-65 signature over the canonical
// envelope digest. The envelope verifier is pure-function and runs in
// the wire path before any store I/O.
//
// Authorization is consensus-native (see consensus_auth.go). The kmsd
// holds one ConsensusAuthorizer; the authorizer asks consensus "is
// this verified NodeID a member of the current validator authority?
// for writes, additionally the operator authority?". There is no
// CSV ACL, no fallback path. If the authorizer is unconfigured the
// server refuses to boot.
package zapserver

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	kmszap "github.com/luxfi/kms/pkg/zap"
	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/log"
	"github.com/luxfi/zap"
)

const (
	OpSecretGet    uint16 = 0x0040
	OpSecretPut    uint16 = 0x0041
	OpSecretList   uint16 = 0x0042
	OpSecretDelete uint16 = 0x0043
)

// status byte values in the response.
const (
	statusOK       byte = 0x00
	statusNotFound byte = 0x01
	statusError    byte = 0x02
	statusForbid   byte = 0x03
)

// Server wires a SecretStore onto a ZAP Node. It does not own the node's
// lifecycle — the caller registers the server and starts the node.
type Server struct {
	store     *store.SecretStore
	masterKey []byte
	authz     ConsensusAuthorizer
	log       log.Logger
	now       func() time.Time

	// Per-peer hybrid handshake sessions. Keyed by ZAP NodeID. A peer
	// with no entry has not run the application-layer hybrid handshake
	// — its requests still flow in the clear (forward-only fallback for
	// peers that don't speak the new opcodes). A peer with an entry
	// gets every payload AEAD-sealed under the derived session key.
	sessions   map[string]*kmszap.Session
	sessionsMu sync.RWMutex
	// localCaps controls what the server advertises in ServerHello.
	// Bit 0 = ML-KEM-768 supported. Defaults to CapMLKEM768 in New().
	localCaps uint16
}

// Config wires a Server with the required dependencies.
type Config struct {
	Store     *store.SecretStore
	MasterKey []byte
	// Authorizer is the consensus-native authorization predicate. The
	// kmsd asks this every request: "is the verified envelope identity
	// authorized for op on path?". Required; nil refuses to boot.
	// See consensus_auth.go.
	Authorizer ConsensusAuthorizer
	// Logger is the luxfi/log Logger. nil falls back to the package
	// root logger (log.Root()).
	Logger log.Logger
	// Now is the wall-clock used for envelope freshness checks. nil
	// defaults to time.Now. Tests pin this.
	Now func() time.Time
}

// New returns a Server ready to attach to a ZAP node via Register.
// Panics if masterKey is not 32 bytes (caller must unseal first) or if
// the authorizer is nil (the server is fail-closed by construction —
// there is no open mode).
func New(cfg Config) *Server {
	if len(cfg.MasterKey) != 32 {
		panic("zapserver: master key must be 32 bytes")
	}
	if cfg.Authorizer == nil {
		panic("zapserver: consensus authorizer is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Root()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{
		store:     cfg.Store,
		masterKey: cfg.MasterKey,
		authz:     cfg.Authorizer,
		log:       cfg.Logger,
		now:       cfg.Now,
		sessions:  make(map[string]*kmszap.Session),
		localCaps: kmszap.CapMLKEM768,
	}
	s.log.Info("kms.zap consensus-native authorization wired")
	return s
}

// Register attaches the Server's handlers to the ZAP Node.
//
// Handlers are registered at both the opcode-specific message type (for
// callers that set the ZAP flags/type field correctly) AND at type 0 (the
// default when callers use zap.Builder without setting flags). Type 0 is a
// universal multiplexer that reads the opcode from the first 2 bytes of the
// payload and dispatches internally.
func (s *Server) Register(n *zap.Node) {
	// Per-opcode handlers. Each runs envelope verification +
	// consensus authorization in wrap() before dispatching to the
	// inner handler.
	n.Handle(OpSecretGet, s.wrap(OpSecretGet, s.handleGet))
	n.Handle(OpSecretPut, s.wrap(OpSecretPut, s.handlePut))
	n.Handle(OpSecretList, s.wrap(OpSecretList, s.handleList))
	n.Handle(OpSecretDelete, s.wrap(OpSecretDelete, s.handleDelete))
	// Application-layer hybrid handshake. Distinct from the secret
	// opcodes so a session is established before any get/put runs.
	n.Handle(kmszap.OpClientHello, s.handleHandshake)

	// Universal handler at type 0: reads opcode from body, dispatches
	// through the same wrap() path so envelope verification and
	// consensus authorization run identically to the per-opcode case.
	handlers := map[uint16]handlerFn{
		OpSecretGet:    s.handleGet,
		OpSecretPut:    s.handlePut,
		OpSecretList:   s.handleList,
		OpSecretDelete: s.handleDelete,
	}
	n.Handle(0, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
		raw := msg.Root().Bytes(0)
		if raw == nil {
			// Fallback: caller wrote raw bytes via Builder.WriteBytes without
			// an enclosing Object — strip the 16-byte ZAP frame header.
			b := msg.Bytes()
			if len(b) > zap.HeaderSize {
				raw = b[zap.HeaderSize:]
			}
		}
		if len(raw) < 2 {
			return respond(statusError, errJSON("empty payload")), nil
		}
		op := binary.LittleEndian.Uint16(raw[:2])
		payload := raw[2:]
		// Hybrid handshake on the universal mux path too.
		if op == kmszap.OpClientHello {
			return s.respondHandshake(from, payload), nil
		}
		h, ok := handlers[op]
		if !ok {
			return respond(statusError, errJSON("unknown opcode")), nil
		}
		// If this peer already negotiated a session, the payload is
		// expected to be AEAD-sealed; open it before dispatch and seal
		// the response.
		sess := s.session(from)
		if sess != nil {
			pt, err := sess.Open(kmszap.DirClientToServer, payload)
			if err != nil {
				s.log.Warn("kms.zap session open failed", "from", from, "op", op, "err", err)
				return respond(statusError, errJSON("session decrypt failed")), nil
			}
			payload = pt
		}
		ident, innerReq, decisionErr := s.verifyAndAuthorize(ctx, payload, op)
		if decisionErr != nil {
			s.log.Info("kms.zap authz",
				"decision", "forbid",
				"op", Op(op).String(),
				"from", from,
				"reason", decisionErr.Error(),
			)
			return s.respondMaybeSealed(from, statusForbid, errJSON(decisionErr.Error())), nil
		}
		status, body, err := h(ctx, ident, innerReq)
		if err != nil {
			s.log.Warn("kms.zap handler error (mux)", "ident", ident.String(), "op", Op(op).String(), "err", err)
			return s.respondMaybeSealed(from, statusError, errJSON(err.Error())), nil
		}
		return s.respondMaybeSealed(from, status, body), nil
	})
}

// session returns the active hybrid session for a peer, or nil if the
// peer has not run OpClientHello yet (forward-compat fallback).
func (s *Server) session(peerID string) *kmszap.Session {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	return s.sessions[peerID]
}

// setSession stores a freshly negotiated session, replacing any prior
// entry for the same peer. Replacing is the sane behaviour: a new
// ClientHello means the client wants to rotate.
func (s *Server) setSession(peerID string, sess *kmszap.Session) {
	s.sessionsMu.Lock()
	s.sessions[peerID] = sess
	s.sessionsMu.Unlock()
}

// respondMaybeSealed builds a status||body reply, sealing the body bytes
// under the peer's session key if one exists. Plaintext fallback is a
// design property for peers that never ran the handshake.
func (s *Server) respondMaybeSealed(peerID string, status byte, body []byte) *zap.Message {
	if sess := s.session(peerID); sess != nil {
		sealed, err := sess.Seal(kmszap.DirServerToClient, body)
		if err != nil {
			s.log.Error("kms.zap seal failed", "from", peerID, "err", err)
			return respond(statusError, errJSON("session seal failed"))
		}
		return respond(status, sealed)
	}
	return respond(status, body)
}

// handleHandshake is the per-opcode handler entry for OpClientHello.
func (s *Server) handleHandshake(_ context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	raw := msg.Root().Bytes(0)
	if raw == nil {
		b := msg.Bytes()
		if len(b) > zap.HeaderSize {
			raw = b[zap.HeaderSize:]
		}
	}
	if len(raw) < 2 {
		return respond(statusError, errJSON("empty handshake payload")), nil
	}
	// Strip the 2-byte opcode prefix written by the client mux.
	return s.respondHandshake(from, raw[2:]), nil
}

// respondHandshake runs the server side of the hybrid PQ handshake,
// installs the resulting session, and frames the ServerHello bytes as
// the response payload (status=OK).
//
// On capability fallback (peer cleared bit 0), we emit a one-line WARN
// so operators can spot stragglers, and we still install the session
// (X25519-only — combined-secret length is still 32 bytes).
func (s *Server) respondHandshake(from string, helloBytes []byte) *zap.Message {
	replyWire, result, err := kmszap.ServerRespond(s.localCaps, helloBytes)
	if err != nil {
		s.log.Warn("kms.zap handshake failed", "from", from, "err", err)
		return respond(statusError, errJSON(err.Error()))
	}
	sess, err := kmszap.NewSession(result.SessionKey, result.Hybrid)
	if err != nil {
		s.log.Error("kms.zap session init failed", "from", from, "err", err)
		return respond(statusError, errJSON(err.Error()))
	}
	s.setSession(from, sess)
	if !result.Hybrid {
		s.log.Warn("kms.zap handshake classical-only — peer cleared ML-KEM-768 cap bit",
			"from", from, "peerCaps", result.PeerCaps)
	} else {
		s.log.Info("kms.zap handshake hybrid", "from", from, "alg", "X25519+ML-KEM-768")
	}
	// ServerHello rides as the body — never AEAD-wrapped, since the key
	// only exists after this exchange completes.
	return respond(statusOK, replyWire)
}

// handlerFn is the shape of our op handlers after envelope unwrap.
// Identity is the verified service identity carried by the envelope;
// payload is the inner request bytes (Envelope.Req).
type handlerFn func(ctx context.Context, ident Identity, payload []byte) (byte, []byte, error)

// wrap marshals the {status || body} response and logs errors with the
// caller's verified identity. When the peer has an active hybrid
// session, the inbound payload is AEAD-opened and the response body
// is sealed. The envelope is parsed, verified, and authorized before
// the inner handler is invoked; failures short-circuit with
// statusForbid and the reason recorded in the audit log.
func (s *Server) wrap(op uint16, h handlerFn) zap.Handler {
	return func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
		// Access body via Root Object. Builder writes the payload at field 0.
		raw := msg.Root().Bytes(0)
		if raw == nil {
			// Fallback: raw frame bytes (for callers that don't use structured
			// objects) — strip the 16-byte ZAP header so payload begins with the
			// opcode prefix.
			b := msg.Bytes()
			if len(b) > zap.HeaderSize {
				raw = b[zap.HeaderSize:]
			}
		}
		// Opcode was already matched by Node — but we carry it in for tracing.
		if len(raw) < 2 {
			return respond(statusError, errJSON("empty payload")), nil
		}
		payload := raw[2:]
		if sess := s.session(from); sess != nil {
			pt, err := sess.Open(kmszap.DirClientToServer, payload)
			if err != nil {
				s.log.Warn("kms.zap session open failed", "from", from, "err", err)
				return respond(statusError, errJSON("session decrypt failed")), nil
			}
			payload = pt
		}
		ident, innerReq, decisionErr := s.verifyAndAuthorize(ctx, payload, op)
		if decisionErr != nil {
			s.log.Info("kms.zap authz",
				"decision", "forbid",
				"op", Op(op).String(),
				"from", from,
				"reason", decisionErr.Error(),
			)
			return s.respondMaybeSealed(from, statusForbid, errJSON(decisionErr.Error())), nil
		}
		status, body, err := h(ctx, ident, innerReq)
		if err != nil {
			s.log.Warn("kms.zap handler error", "ident", ident.String(), "op", Op(op).String(), "err", err)
			return s.respondMaybeSealed(from, statusError, errJSON(err.Error())), nil
		}
		return s.respondMaybeSealed(from, status, body), nil
	}
}

// verifyAndAuthorize is the canonical request entry: parse envelope,
// verify signature + freshness, run the consensus authorizer, return
// the verified Identity + the inner request bytes.
//
// On any failure the returned error is a single sentence safe for the
// wire (no internal state). The caller emits the audit row and writes
// statusForbid.
func (s *Server) verifyAndAuthorize(ctx context.Context, raw []byte, op uint16) (Identity, []byte, error) {
	env, err := ParseEnvelope(raw)
	if err != nil {
		return Identity{}, nil, fmt.Errorf("envelope: %w", err)
	}
	if env.Op != op {
		return Identity{}, nil, fmt.Errorf("envelope: op mismatch (got 0x%04X want 0x%04X)", env.Op, op)
	}
	ident, err := VerifyEnvelope(env, s.now())
	if err != nil {
		return Identity{}, nil, err
	}
	path, err := pathFromInnerRequest(op, env.Req)
	if err != nil {
		return Identity{}, nil, err
	}
	decision, err := s.authz.Authorize(ctx, ident, path, Op(op))
	if err != nil {
		return Identity{}, nil, fmt.Errorf("consensus: %s: %w", decision.Reason, err)
	}
	if !decision.Allow {
		return Identity{}, nil, fmt.Errorf("forbidden: %s", decision.Reason)
	}
	return ident, []byte(env.Req), nil
}

// pathFromInnerRequest extracts the canonical "path" from the opcode's
// inner JSON request shape. Each opcode has a single `path` field;
// missing → "" which the authorizer treats as the root prefix.
func pathFromInnerRequest(op uint16, req json.RawMessage) (string, error) {
	if len(req) == 0 {
		return "", errors.New("envelope: empty inner request")
	}
	var anyReq struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(req, &anyReq); err != nil {
		return "", fmt.Errorf("envelope: inner: %w", err)
	}
	return anyReq.Path, nil
}

// respond frames { status || json } as a ZAP message.
func respond(status byte, body []byte) *zap.Message {
	b := zap.NewBuilder(len(body) + 8)
	b.WriteBytes(append([]byte{status}, body...))
	raw := b.Finish()
	msg, err := zap.Parse(raw)
	if err != nil {
		// Should never happen — Builder output is always parseable.
		return nil
	}
	return msg
}

func errJSON(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return b
}

// ---- handlers ----

// The four secret-opcode handlers. Each receives the verified Identity
// (from envelope verification + consensus authorization) and the inner
// request JSON bytes (Envelope.Req). Handlers do not re-check auth —
// that is the wrap() path's responsibility.

type getReq struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Env  string `json:"env"`
}

type getResp struct {
	Value string `json:"value"` // base64 plaintext
}

func (s *Server) handleGet(_ context.Context, ident Identity, payload []byte) (byte, []byte, error) {
	var req getReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return statusError, errJSON(err.Error()), nil
	}
	sec, err := s.store.Get(req.Path, req.Name, req.Env)
	if errors.Is(err, store.ErrSecretNotFound) {
		return statusNotFound, errJSON("not found"), nil
	}
	if err != nil {
		return statusError, nil, err
	}
	pt, err := store.Open(s.masterKey, sec)
	if err != nil {
		return statusError, nil, err
	}
	defer zero(pt)
	b, _ := json.Marshal(getResp{Value: base64.StdEncoding.EncodeToString(pt)})
	s.log.Debug("kms.zap get", "ident", ident.String(), "path", req.Path, "name", req.Name, "env", req.Env)
	return statusOK, b, nil
}

type putReq struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Env   string `json:"env"`
	Value string `json:"value"` // base64 plaintext
}

func (s *Server) handlePut(_ context.Context, ident Identity, payload []byte) (byte, []byte, error) {
	var req putReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return statusError, errJSON(err.Error()), nil
	}
	pt, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		return statusError, errJSON("bad base64"), nil
	}
	defer zero(pt)
	sec, err := store.Seal(s.masterKey, req.Path, req.Name, req.Env, pt)
	if err != nil {
		return statusError, nil, err
	}
	if err := s.store.Put(sec); err != nil {
		return statusError, nil, err
	}
	s.log.Info("kms.zap put", "ident", ident.String(), "path", req.Path, "name", req.Name, "env", req.Env)
	b, _ := json.Marshal(map[string]bool{"ok": true})
	return statusOK, b, nil
}

type listReq struct {
	Path string `json:"path"`
	Env  string `json:"env"`
}

type listResp struct {
	Names []string `json:"names"`
}

func (s *Server) handleList(_ context.Context, ident Identity, payload []byte) (byte, []byte, error) {
	var req listReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return statusError, errJSON(err.Error()), nil
	}
	secs, err := s.store.List(req.Path, req.Env)
	if err != nil {
		return statusError, nil, err
	}
	names := make([]string, 0, len(secs))
	for _, sec := range secs {
		names = append(names, sec.Name)
	}
	s.log.Debug("kms.zap list", "ident", ident.String(), "path", req.Path, "env", req.Env)
	b, _ := json.Marshal(listResp{Names: names})
	return statusOK, b, nil
}

type delReq struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Env  string `json:"env"`
}

func (s *Server) handleDelete(_ context.Context, ident Identity, payload []byte) (byte, []byte, error) {
	var req delReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return statusError, errJSON(err.Error()), nil
	}
	if err := s.store.Delete(req.Path, req.Name, req.Env); err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			return statusNotFound, errJSON("not found"), nil
		}
		return statusError, nil, err
	}
	s.log.Info("kms.zap delete", "ident", ident.String(), "path", req.Path, "name", req.Name, "env", req.Env)
	b, _ := json.Marshal(map[string]bool{"ok": true})
	return statusOK, b, nil
}

// zero wipes a byte slice (best effort — caller must still avoid copies).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// BuildRequest is a helper for clients: frames opcode(2 LE) || JSON payload.
// Returns the raw bytes ready for zap.NewBuilder.WriteBytes.
func BuildRequest(op uint16, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	out := make([]byte, 2+len(data))
	binary.LittleEndian.PutUint16(out[0:2], op)
	copy(out[2:], data)
	return out, nil
}

// ParseResponse extracts the status byte and JSON body from a reply message.
func ParseResponse(raw []byte) (status byte, body []byte, err error) {
	if len(raw) < 1 {
		return 0, nil, fmt.Errorf("empty response")
	}
	return raw[0], raw[1:], nil
}
