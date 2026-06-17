// Package zap implements the application-layer hybrid post-quantum
// handshake for the KMS ZAP wire protocol.
//
// LP-022 specifies that ZAP transport runs over TLS 1.3 with Go 1.26's
// X25519MLKEM768 native hybrid curve. That covers the ingress path. For
// pod-to-pod traffic that does NOT route through ingress (in-cluster
// ZAP-to-ZAP), the connection is plaintext or classical-TLS only — no
// post-quantum key agreement at the wire layer.
//
// This package adds an application-layer hybrid handshake on top of
// every ZAP connection, irrespective of TLS configuration:
//
//  1. Classical X25519 ECDH (RFC 7748).
//  2. ML-KEM-768 KEM encapsulation (FIPS 203 / NIST PQC Level 3).
//  3. Combined shared secret = HKDF-SHA256(X25519_shared || MLKEM_shared).
//  4. Derived AES-256-GCM session key for the rest of the connection.
//
// Capability negotiation: a 2-byte cap bitmap rides in every hello frame.
// Bit 0 = ML-KEM-768 supported. If a peer clears bit 0, both sides fall
// back to classical-only and log a warning. The fallback path exists for
// inter-version compatibility — a forward-only stack would refuse, but
// at the wire level refusing breaks rolling upgrades.
//
// Wire format (little-endian where multi-byte):
//
//   ClientHello (frame opcode 0x00F0):
//     +0   uint16 caps         // bit 0 = ML-KEM-768 supported
//     +2   [32]byte x25519_pk  // ephemeral X25519 public key
//     +34  [1184]byte mlkem_pk // ML-KEM-768 public key (omit if !cap0)
//
//   ServerHello (frame opcode 0x00F1):
//     +0    uint16 caps         // bit 0 echoed (set iff both sides support)
//     +2    [32]byte x25519_pk  // ephemeral X25519 public key
//     +34   [1088]byte mlkem_ct // ML-KEM-768 ciphertext (omit if !cap0)
//
// The combined secret feeds HKDF-SHA256 with info "kms/zap/v1/session"
// and a transcript hash salt (SHA-256 of the concatenated hello frames).
// Output is a 32-byte AES-256-GCM session key.
//
// Backwards-compat: a peer that doesn't speak this opcode set will
// return a ZAP error or unknown-handler reply — the client treats that
// as "no PQ handshake available" and proceeds in classical-only mode
// (X25519-only, with a one-line warning). A KMS instance running this
// package always advertises bit 0 set.
package zap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	mlkem "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/hkdf"
)

// HandshakeOpcodes are reserved at the high end of the KMS opcode space.
// See pkg/zapserver/server.go (OpSecret* = 0x0040..0x0043). 0x00F0/0x00F1
// avoid the secret opcode block and any future extensions there.
const (
	OpClientHello uint16 = 0x00F0
	OpServerHello uint16 = 0x00F1
)

// Capability bits. A peer ANDs its caps with the remote caps and uses
// the intersection to decide which key-agreement primitives to run.
const (
	CapMLKEM768 uint16 = 1 << 0
)

// Sizes per FIPS 203 (ML-KEM-768) and RFC 7748 (X25519).
const (
	X25519PubSize  = 32
	X25519PrivSize = 32
	MLKEMPubSize   = mlkem.PublicKeySize  // 1184
	MLKEMCtSize    = mlkem.CiphertextSize // 1088
	MLKEMSharedSize = mlkem.SharedKeySize // 32

	SessionKeySize = 32 // AES-256-GCM
)

// Errors.
var (
	ErrTruncated     = errors.New("zap/handshake: frame truncated")
	ErrCapMismatch   = errors.New("zap/handshake: peer rejected ML-KEM-768")
	ErrInvalidPubKey = errors.New("zap/handshake: invalid public key")
)

// HandshakeResult is the output of a completed handshake. SessionKey is
// 32 bytes suitable for AES-256-GCM. Hybrid is true iff ML-KEM-768 ran.
type HandshakeResult struct {
	SessionKey []byte // 32 bytes
	Hybrid     bool   // true = X25519+ML-KEM-768; false = X25519 only
	PeerCaps   uint16 // capability bitmap the peer advertised
}

// ClientHelloFrame is the parsed first message a client sends.
type ClientHelloFrame struct {
	Caps      uint16
	X25519Pub [X25519PubSize]byte
	MLKEMPub  []byte // len == MLKEMPubSize iff caps&CapMLKEM768
}

// ServerHelloFrame is the parsed reply.
type ServerHelloFrame struct {
	Caps      uint16
	X25519Pub [X25519PubSize]byte
	MLKEMCt   []byte // len == MLKEMCtSize iff caps&CapMLKEM768
}

// ClientState holds the ephemeral private keys a client needs to keep
// between sending hello and processing the server reply.
type ClientState struct {
	caps         uint16
	x25519Priv   *ecdh.PrivateKey
	mlkemPriv    *mlkem.PrivateKey
	helloBytes   []byte // serialized client hello, used in transcript hash
}

// ServerState holds keys derived during a server-side encapsulation; the
// caller produces a ServerHelloFrame and a SessionKey atomically via
// ServerRespond.
type ServerState struct {
	helloBytes []byte // serialized server hello
}

// NewClient generates ephemeral key material and serializes a
// ClientHello. localCaps controls what the client offers; bit 0 set
// requests ML-KEM-768.
func NewClient(localCaps uint16) (*ClientState, []byte, error) {
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("zap/handshake: gen X25519: %w", err)
	}
	st := &ClientState{caps: localCaps, x25519Priv: xPriv}

	frame := &ClientHelloFrame{Caps: localCaps}
	copy(frame.X25519Pub[:], xPriv.PublicKey().Bytes())

	if localCaps&CapMLKEM768 != 0 {
		mPub, mPriv, err := mlkem.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("zap/handshake: gen ML-KEM: %w", err)
		}
		st.mlkemPriv = mPriv
		buf := make([]byte, MLKEMPubSize)
		mPub.Pack(buf)
		frame.MLKEMPub = buf
	}

	wire, err := MarshalClientHello(frame)
	if err != nil {
		return nil, nil, err
	}
	st.helloBytes = wire
	return st, wire, nil
}

// ServerRespond consumes a serialized ClientHello, performs X25519 ECDH
// and (if both peers offer ML-KEM-768) ML-KEM encapsulation, and returns
// (ServerHello bytes, session key, hybrid bool, error).
//
// localCaps is what the server supports. The reply caps are the AND of
// local and remote caps.
func ServerRespond(localCaps uint16, clientHelloWire []byte) (replyWire []byte, result *HandshakeResult, err error) {
	client, err := UnmarshalClientHello(clientHelloWire)
	if err != nil {
		return nil, nil, err
	}

	negotiated := localCaps & client.Caps
	hybrid := negotiated&CapMLKEM768 != 0

	// Classical X25519 ECDH.
	clientX, err := ecdh.X25519().NewPublicKey(client.X25519Pub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: X25519: %v", ErrInvalidPubKey, err)
	}
	serverXPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("zap/handshake: gen X25519: %w", err)
	}
	xShared, err := serverXPriv.ECDH(clientX)
	if err != nil {
		return nil, nil, fmt.Errorf("zap/handshake: X25519 ECDH: %w", err)
	}

	reply := &ServerHelloFrame{Caps: negotiated}
	copy(reply.X25519Pub[:], serverXPriv.PublicKey().Bytes())

	var mlkemShared []byte
	if hybrid {
		if len(client.MLKEMPub) != MLKEMPubSize {
			return nil, nil, fmt.Errorf("%w: ML-KEM pubkey size %d", ErrInvalidPubKey, len(client.MLKEMPub))
		}
		var pk mlkem.PublicKey
		if err := pk.Unpack(client.MLKEMPub); err != nil {
			return nil, nil, fmt.Errorf("%w: ML-KEM unpack: %v", ErrInvalidPubKey, err)
		}
		ct := make([]byte, MLKEMCtSize)
		ss := make([]byte, MLKEMSharedSize)
		seed := make([]byte, mlkem.EncapsulationSeedSize)
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return nil, nil, fmt.Errorf("zap/handshake: rand seed: %w", err)
		}
		pk.EncapsulateTo(ct, ss, seed)
		reply.MLKEMCt = ct
		mlkemShared = ss
	}

	replyWire, err = MarshalServerHello(reply)
	if err != nil {
		return nil, nil, err
	}

	sessionKey := combineAndDerive(xShared, mlkemShared, clientHelloWire, replyWire)
	return replyWire, &HandshakeResult{
		SessionKey: sessionKey,
		Hybrid:     hybrid,
		PeerCaps:   client.Caps,
	}, nil
}

// ClientFinish consumes a ServerHello and finalizes the session key.
func (c *ClientState) ClientFinish(serverHelloWire []byte) (*HandshakeResult, error) {
	server, err := UnmarshalServerHello(serverHelloWire)
	if err != nil {
		return nil, err
	}

	hybrid := server.Caps&CapMLKEM768 != 0 && c.caps&CapMLKEM768 != 0
	if (c.caps&CapMLKEM768 != 0) && !hybrid {
		// Peer cleared the bit; we requested it. This is the documented
		// fallback path — caller logs the warning, we just continue.
	}

	serverX, err := ecdh.X25519().NewPublicKey(server.X25519Pub[:])
	if err != nil {
		return nil, fmt.Errorf("%w: X25519: %v", ErrInvalidPubKey, err)
	}
	xShared, err := c.x25519Priv.ECDH(serverX)
	if err != nil {
		return nil, fmt.Errorf("zap/handshake: X25519 ECDH: %w", err)
	}

	var mlkemShared []byte
	if hybrid {
		if c.mlkemPriv == nil {
			return nil, errors.New("zap/handshake: ML-KEM priv missing on client")
		}
		if len(server.MLKEMCt) != MLKEMCtSize {
			return nil, fmt.Errorf("%w: ML-KEM ct size %d", ErrInvalidPubKey, len(server.MLKEMCt))
		}
		ss := make([]byte, MLKEMSharedSize)
		c.mlkemPriv.DecapsulateTo(ss, server.MLKEMCt)
		mlkemShared = ss
	}

	sessionKey := combineAndDerive(xShared, mlkemShared, c.helloBytes, serverHelloWire)
	return &HandshakeResult{
		SessionKey: sessionKey,
		Hybrid:     hybrid,
		PeerCaps:   server.Caps,
	}, nil
}

// combineAndDerive runs the NIST hybrid construction:
//
//	IKM      = X25519_shared || ML_KEM_shared
//	salt     = SHA-256(client_hello || server_hello)
//	info     = "kms/zap/v1/session"
//	session  = HKDF-SHA256(IKM, salt, info, 32)
//
// When hybrid is false (mlkemShared == nil), IKM = X25519_shared alone.
func combineAndDerive(xShared, mlkemShared, clientHello, serverHello []byte) []byte {
	ikm := make([]byte, 0, len(xShared)+len(mlkemShared))
	ikm = append(ikm, xShared...)
	if mlkemShared != nil {
		ikm = append(ikm, mlkemShared...)
	}

	var salt [sha256.Size]byte
	h := sha256.New()
	h.Write(clientHello)
	h.Write(serverHello)
	h.Sum(salt[:0])

	r := hkdf.New(newSHA256, ikm, salt[:], []byte("kms/zap/v1/session"))
	out := make([]byte, SessionKeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		// HKDF over a fixed-size SHA-256 with 32-byte output is
		// infallible. Treat as an unrecoverable invariant violation.
		panic(fmt.Sprintf("zap/handshake: hkdf: %v", err))
	}
	return out
}

func newSHA256() hash.Hash { return sha256.New() }

// SessionAEAD wraps a 32-byte session key in an AES-256-GCM AEAD ready
// for sealing or opening frame payloads. Nonce management is the
// caller's responsibility — typical usage is a per-frame counter
// concatenated with a per-direction salt.
func SessionAEAD(sessionKey []byte) (cipher.AEAD, error) {
	if len(sessionKey) != SessionKeySize {
		return nil, fmt.Errorf("zap/handshake: session key must be %d bytes", SessionKeySize)
	}
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("zap/handshake: aes.NewCipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// ---- wire (de)serialization ----

// MarshalClientHello serializes a ClientHelloFrame to its on-the-wire
// byte representation. See the ClientHello layout in the package doc.
func MarshalClientHello(f *ClientHelloFrame) ([]byte, error) {
	size := 2 + X25519PubSize
	if f.Caps&CapMLKEM768 != 0 {
		if len(f.MLKEMPub) != MLKEMPubSize {
			return nil, fmt.Errorf("zap/handshake: ML-KEM pub must be %d bytes, got %d", MLKEMPubSize, len(f.MLKEMPub))
		}
		size += MLKEMPubSize
	}
	out := make([]byte, size)
	binary.LittleEndian.PutUint16(out[0:2], f.Caps)
	copy(out[2:2+X25519PubSize], f.X25519Pub[:])
	if f.Caps&CapMLKEM768 != 0 {
		copy(out[2+X25519PubSize:], f.MLKEMPub)
	}
	return out, nil
}

// UnmarshalClientHello parses a ClientHello wire frame.
func UnmarshalClientHello(b []byte) (*ClientHelloFrame, error) {
	if len(b) < 2+X25519PubSize {
		return nil, fmt.Errorf("%w: client hello %d bytes", ErrTruncated, len(b))
	}
	f := &ClientHelloFrame{
		Caps: binary.LittleEndian.Uint16(b[0:2]),
	}
	copy(f.X25519Pub[:], b[2:2+X25519PubSize])
	if f.Caps&CapMLKEM768 != 0 {
		off := 2 + X25519PubSize
		if len(b) < off+MLKEMPubSize {
			return nil, fmt.Errorf("%w: ML-KEM pub", ErrTruncated)
		}
		f.MLKEMPub = make([]byte, MLKEMPubSize)
		copy(f.MLKEMPub, b[off:off+MLKEMPubSize])
	}
	return f, nil
}

// MarshalServerHello serializes a ServerHelloFrame.
func MarshalServerHello(f *ServerHelloFrame) ([]byte, error) {
	size := 2 + X25519PubSize
	if f.Caps&CapMLKEM768 != 0 {
		if len(f.MLKEMCt) != MLKEMCtSize {
			return nil, fmt.Errorf("zap/handshake: ML-KEM ct must be %d bytes, got %d", MLKEMCtSize, len(f.MLKEMCt))
		}
		size += MLKEMCtSize
	}
	out := make([]byte, size)
	binary.LittleEndian.PutUint16(out[0:2], f.Caps)
	copy(out[2:2+X25519PubSize], f.X25519Pub[:])
	if f.Caps&CapMLKEM768 != 0 {
		copy(out[2+X25519PubSize:], f.MLKEMCt)
	}
	return out, nil
}

// UnmarshalServerHello parses a ServerHello wire frame.
func UnmarshalServerHello(b []byte) (*ServerHelloFrame, error) {
	if len(b) < 2+X25519PubSize {
		return nil, fmt.Errorf("%w: server hello %d bytes", ErrTruncated, len(b))
	}
	f := &ServerHelloFrame{
		Caps: binary.LittleEndian.Uint16(b[0:2]),
	}
	copy(f.X25519Pub[:], b[2:2+X25519PubSize])
	if f.Caps&CapMLKEM768 != 0 {
		off := 2 + X25519PubSize
		if len(b) < off+MLKEMCtSize {
			return nil, fmt.Errorf("%w: ML-KEM ct", ErrTruncated)
		}
		f.MLKEMCt = make([]byte, MLKEMCtSize)
		copy(f.MLKEMCt, b[off:off+MLKEMCtSize])
	}
	return f, nil
}
