// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// node_id_scheme.go — wire-discriminated NodeID derivation.
//
// The 20-byte NodeID array kept in node_id.go is the canonical storage and
// map-key form: it is the truncation of a domain-separated, scheme-tagged
// digest of a validator's public key. This file owns the discrimination
// surface — what *kind* of key produced this NodeID — without changing the
// 20-byte array width, which is load-bearing for every map / codec / DB key
// in the wider node codebase.
//
// Derivation surface:
//
//	strict-PQ (ML-DSA-65 / ML-DSA-87):
//	  digest    = SHAKE256-384("NODE_ID_V1" || chain_id || scheme || pubkey)
//	  NodeID    = digest[:20]                               (storage / map key)
//	  FullDigest = digest                                   (handshake transcript)
//
//	classical (secp256k1 cert, CLASSICAL_COMPAT_UNSAFE only):
//	  NodeID = RIPEMD160(SHA256(cert.Raw))   (existing NodeIDFromCert behaviour)
//
// Wire form (TypedNodeID): one leading scheme byte || 20-byte NodeID. The
// scheme byte travels on the wire so a receiver knows how to verify before
// consulting the chain profile. The profile is a downgrade-detection gate;
// the scheme byte is a primitive-mismatch gate.
//
// The 20-byte truncation provides ~80-bit collision resistance — the same
// bound the existing RIPEMD160-based NodeID has against a quantum adversary
// running Grover. Full 384-bit commitment is available via FullDigest() for
// the validator-set commitment that pins post-quantum security at genesis.

package ids

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// NodeIDScheme is the wire byte that identifies which keying material
// produced a NodeID. Numbering aligns with the consensus
// SigSchemeID/WalletSchemeID enum blocks so the byte itself reads the same
// in every transcript:
//
//	0x00       — Invalid (never accepted)
//	0x42       — ML-DSA-65   (FIPS 204 Cat 3, canonical strict-PQ)
//	0x43       — ML-DSA-87   (FIPS 204 Cat 5, high-value validators)
//	0x90       — secp256k1   (classical; accepted ONLY under
//	             LUX_CLASSICAL_COMPAT_UNSAFE)
//
// New schemes claim the next free byte in the matching consensus block.
// Reuse is forbidden — a retired byte stays retired.
type NodeIDScheme uint8

const (
	// NodeIDSchemeInvalid is the zero value. Any decode that produces it
	// is an error; any encode that names it is a bug.
	NodeIDSchemeInvalid NodeIDScheme = 0x00

	// NodeIDSchemeMLDSA65 is the canonical strict-PQ NodeID scheme. The
	// matching identity signature scheme is SigSchemeMLDSA65 in
	// luxfi/consensus/config.
	NodeIDSchemeMLDSA65 NodeIDScheme = 0x42

	// NodeIDSchemeMLDSA87 is the high-value strict-PQ NodeID scheme used
	// for validators that secure governance roots / treasury operations.
	// The matching identity signature scheme is SigSchemeMLDSA87.
	NodeIDSchemeMLDSA87 NodeIDScheme = 0x43

	// NodeIDSchemeSecp256k1 is the legacy classical scheme. Accepted only
	// when a chain explicitly opts into LUX_CLASSICAL_COMPAT_UNSAFE; any
	// strict-PQ profile rejects it. The 0x90 byte mirrors the consensus
	// "forbidden in PQ mode" block so an audit pipeline can flag a leak.
	NodeIDSchemeSecp256k1 NodeIDScheme = 0x90
)

// String returns the canonical wire name of this scheme.
func (s NodeIDScheme) String() string {
	switch s {
	case NodeIDSchemeInvalid:
		return "invalid"
	case NodeIDSchemeMLDSA65:
		return "ml-dsa-65"
	case NodeIDSchemeMLDSA87:
		return "ml-dsa-87"
	case NodeIDSchemeSecp256k1:
		return "secp256k1-classical-compat-unsafe"
	default:
		return fmt.Sprintf("node-id-scheme(0x%02x)", uint8(s))
	}
}

// IsPostQuantum reports whether this scheme is post-quantum (FIPS 204
// ML-DSA family). Strict-PQ profiles refuse any NodeID whose scheme is
// not post-quantum.
func (s NodeIDScheme) IsPostQuantum() bool {
	return s == NodeIDSchemeMLDSA65 || s == NodeIDSchemeMLDSA87
}

// IsClassicalCompatUnsafe reports whether this scheme is in the classical
// compatibility block (0x90+). These schemes are accepted only under an
// explicit operator opt-in; the strict-PQ profile refuses them.
func (s NodeIDScheme) IsClassicalCompatUnsafe() bool {
	return s == NodeIDSchemeSecp256k1
}

// IsKnown reports whether this byte names a scheme this build understands.
// An unknown byte is rejected by every gate — including the
// classical-compat path, which only accepts the named secp256k1 scheme,
// not arbitrary 0x90+ bytes.
func (s NodeIDScheme) IsKnown() bool {
	switch s {
	case NodeIDSchemeMLDSA65, NodeIDSchemeMLDSA87, NodeIDSchemeSecp256k1:
		return true
	default:
		return false
	}
}

// nodeIDDomainPrefix is the SP 800-185 customization string for the
// SHAKE256-384 derivation. Pinned at "v1"; bumping the string invalidates
// every prior derivation, which is the correct behaviour for a hardfork of
// the derivation encoding.
const nodeIDDomainPrefix = "NODE_ID_V1"

// FullDigestLen is the byte length of the canonical NodeID full digest
// (SHAKE256-384). The 20-byte NodeID is the prefix of this digest; the
// full digest is what handshake transcripts and validator-set commitments
// bind.
const FullDigestLen = 48

// FullDigest is the 48-byte commitment to a validator's identity. The
// 20-byte NodeID is FullDigest[:20]; the full digest is preserved for
// callers that need the post-quantum-strength commitment (handshake
// transcripts, genesis validator-set roots).
type FullDigest [FullDigestLen]byte

// DeriveMLDSA returns the 48-byte SHAKE256-384 digest and matching 20-byte
// NodeID for an ML-DSA public key under the supplied chain id.
//
//	digest = SHAKE256-384(left_encode(len)||"NODE_ID_V1" ||
//	                       chain_id || {scheme} || pubkey)
//	NodeID = digest[:20]
//
// scheme MUST be NodeIDSchemeMLDSA65 or NodeIDSchemeMLDSA87 — any other
// byte is rejected so a caller cannot silently produce an off-spec NodeID
// by passing the wrong scheme tag. chainID is the 32-byte chain identifier
// (typically the ID of the chain the validator stakes on); a different
// chain produces a different NodeID for the same key, which prevents
// cross-chain replay of validator registrations.
func (s NodeIDScheme) DeriveMLDSA(chainID ID, pubKey []byte) (NodeID, FullDigest, error) {
	if s != NodeIDSchemeMLDSA65 && s != NodeIDSchemeMLDSA87 {
		return EmptyNodeID, FullDigest{}, fmt.Errorf("%w: scheme=%s is not ML-DSA",
			ErrNodeIDSchemeInvalid, s.String())
	}
	if len(pubKey) == 0 {
		return EmptyNodeID, FullDigest{}, fmt.Errorf("%w: empty public key",
			ErrNodeIDSchemeInvalid)
	}

	// SP 800-185 left_encode framing on each field so concatenation is
	// unambiguous: a verifier cannot be tricked by a pubkey whose first
	// bytes spell another field's payload.
	h := sha3.NewShake256()
	_, _ = h.Write(leftEncodeNodeID(uint64(len(nodeIDDomainPrefix)) * 8))
	_, _ = h.Write([]byte(nodeIDDomainPrefix))
	_, _ = h.Write(leftEncodeNodeID(uint64(IDLen) * 8))
	_, _ = h.Write(chainID[:])
	_, _ = h.Write(leftEncodeNodeID(8))
	_, _ = h.Write([]byte{byte(s)})
	_, _ = h.Write(leftEncodeNodeID(uint64(len(pubKey)) * 8))
	_, _ = h.Write(pubKey)

	var full FullDigest
	_, _ = h.Read(full[:])

	var id NodeID
	copy(id[:], full[:NodeIDLen])
	return id, full, nil
}

// leftEncodeNodeID is the SP 800-185 §2.3.1 left_encode operation. Kept
// local to this file so node_id_scheme.go has no internal dependency on
// other helpers in the package — the encoding stays reviewable in one
// place. Byte-for-byte identical to the helper in consensus/config.
func leftEncodeNodeID(x uint64) []byte {
	if x == 0 {
		return []byte{0x01, 0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, byte(8-i))
	out = append(out, buf[i:]...)
	return out
}

// TypedNodeIDLen is the byte length of a TypedNodeID on the wire:
// one scheme byte + 20-byte NodeID.
const TypedNodeIDLen = 1 + NodeIDLen

// TypedNodeID is the wire-canonical NodeID: a NodeIDScheme byte followed
// by the 20-byte NodeID. Used at every boundary where the receiver MUST
// know which verifier to dispatch (peer handshake auth check, validator
// registration, block proposer attribution, mempool sender check) without
// relying on the chain profile alone — the profile catches a downgrade
// but not a primitive mismatch.
//
// The 20-byte NodeID is preserved as a map-key / storage primitive; the
// scheme byte travels with it on the wire. In-memory consumers that
// already key by NodeID continue to work unchanged; only the wire
// boundary widens.
type TypedNodeID struct {
	Scheme NodeIDScheme
	NodeID NodeID
}

// NewTypedNodeID constructs a TypedNodeID. The scheme MUST be a known
// scheme; NodeIDSchemeInvalid and unknown bytes are rejected so a caller
// cannot construct a TypedNodeID that the wire decoder would later
// refuse — the construction gate matches the decoding gate.
func NewTypedNodeID(scheme NodeIDScheme, id NodeID) (TypedNodeID, error) {
	if !scheme.IsKnown() {
		return TypedNodeID{}, fmt.Errorf("%w: scheme=%s", ErrNodeIDSchemeInvalid, scheme.String())
	}
	return TypedNodeID{Scheme: scheme, NodeID: id}, nil
}

// Bytes returns the 21-byte wire form: one scheme byte followed by the
// 20-byte NodeID. Callers MUST NOT mutate the returned slice; a future
// version may share the underlying array.
func (t TypedNodeID) Bytes() []byte {
	out := make([]byte, TypedNodeIDLen)
	out[0] = byte(t.Scheme)
	copy(out[1:], t.NodeID[:])
	return out
}

// ParseTypedNodeID is the inverse of TypedNodeID.Bytes. Refuses any input
// that is the wrong length, names NodeIDSchemeInvalid, or names an
// unknown scheme byte. The scheme byte is checked before the NodeID copy
// so a malformed input cannot consume the array space.
func ParseTypedNodeID(b []byte) (TypedNodeID, error) {
	if len(b) != TypedNodeIDLen {
		return TypedNodeID{}, fmt.Errorf("%w: got %d bytes, want %d",
			ErrTypedNodeIDLen, len(b), TypedNodeIDLen)
	}
	s := NodeIDScheme(b[0])
	if !s.IsKnown() {
		return TypedNodeID{}, fmt.Errorf("%w: scheme=0x%02x",
			ErrNodeIDSchemeUnknown, b[0])
	}
	var id NodeID
	copy(id[:], b[1:])
	return TypedNodeID{Scheme: s, NodeID: id}, nil
}

// Compare orders TypedNodeIDs lexicographically over (scheme, id). Used
// for deterministic sorting in validator-set commitments.
func (t TypedNodeID) Compare(other TypedNodeID) int {
	if t.Scheme != other.Scheme {
		if t.Scheme < other.Scheme {
			return -1
		}
		return 1
	}
	return bytes.Compare(t.NodeID[:], other.NodeID[:])
}

// String returns "scheme:NodeID-<cb58>" for logging. Not a wire form.
func (t TypedNodeID) String() string {
	return fmt.Sprintf("%s:%s", t.Scheme.String(), t.NodeID.String())
}

// TypedNodeIDFromCert produces a classical-compat TypedNodeID from a
// staking certificate. Used by the classical-compat handshake path; a
// strict-PQ chain refuses this TypedNodeID at the cross-axis gate.
func TypedNodeIDFromCert(cert *Certificate) TypedNodeID {
	return TypedNodeID{
		Scheme: NodeIDSchemeSecp256k1,
		NodeID: NodeIDFromCert(cert),
	}
}

// TypedNodeIDFromMLDSA produces a strict-PQ TypedNodeID from an ML-DSA
// public key under the supplied chain id. scheme MUST be
// NodeIDSchemeMLDSA65 or NodeIDSchemeMLDSA87; any other byte is rejected.
//
// The returned FullDigest is the 48-byte commitment; callers that bind
// validator identity into a transcript MUST use FullDigest, not the
// 20-byte NodeID alone.
func TypedNodeIDFromMLDSA(
	scheme NodeIDScheme,
	chainID ID,
	pubKey []byte,
) (TypedNodeID, FullDigest, error) {
	id, full, err := scheme.DeriveMLDSA(chainID, pubKey)
	if err != nil {
		return TypedNodeID{}, FullDigest{}, err
	}
	t, err := NewTypedNodeID(scheme, id)
	if err != nil {
		return TypedNodeID{}, FullDigest{}, err
	}
	return t, full, nil
}

// Typed validation errors. Wrapped so consumers can match with errors.Is.
var (
	// ErrNodeIDSchemeInvalid — caller named NodeIDSchemeInvalid or
	// supplied a scheme outside the expected family (e.g. classical
	// scheme on an ML-DSA derivation call).
	ErrNodeIDSchemeInvalid = errors.New("ids: NodeIDScheme is invalid")

	// ErrNodeIDSchemeUnknown — wire byte does not name a scheme this
	// build understands.
	ErrNodeIDSchemeUnknown = errors.New("ids: NodeIDScheme is unknown")

	// ErrTypedNodeIDLen — wire input was not exactly TypedNodeIDLen bytes.
	ErrTypedNodeIDLen = errors.New("ids: TypedNodeID wire length mismatch")

	// ErrNodeIDSchemeMismatch — a TypedNodeID's scheme byte does not
	// match the scheme the consensus profile pins. This is the cross-axis
	// gate that catches a primitive-mismatch downgrade attempt at the
	// chain boundary.
	ErrNodeIDSchemeMismatch = errors.New("ids: NodeIDScheme does not match profile")
)
