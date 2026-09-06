// Package node defines what a Hanzo node's key signs and how anyone checks it.
//
// A Hanzo node is named by a wallet: a secp256k1 keypair whose address is the
// node's identity on the settlement L1, the account its stake is bonded from,
// the account its work rewards pay to, and the row the fleet view lists it
// under. The private key is held by the KMS and returned to nobody, so a node
// does not sign — it asks the KMS to sign, and gets back a statement.
//
// This package is the statement, not the custody. It holds the wire types, the
// preimages the KMS hashes, and the check a verifier runs. It has no store, no
// transport and no server dependency, so the KMS that mints a signature, the
// node daemon that carries one, and the chain indexer that settles on one all
// compile against this same definition. There is no second implementation of a
// preimage to drift from the first.
//
// # The two statements
//
// Every digest is keccak-256 over a fixed-length preimage whose first field is
// the hash of a purpose tag:
//
//	attestation: H( H(tag) ‖ address ‖ measurement ‖ epoch ‖ H(payload) )
//	succession:  H( H(tag) ‖ prev ‖ next ‖ epoch )
//
// Fixed length in every field, so the encoding is injective: no two distinct
// statements share a preimage, and the two purposes cannot collide with each
// other. An Ethereum transaction hash is keccak-256 over an RLP payload with no
// such prefix, so a signature over either statement is not a transaction
// signature other than by second preimage. The key controls funds; this
// protocol cannot move them.
//
// # Verifying against what you expect
//
// [Receipt.Verify] takes the payload the verifier already holds rather than
// trusting one the server echoed, and [Handover.Verify] recomputes its own
// digest before recovering. Both reject a signature whose recovered address is
// not the one the statement names. A caller therefore checks that the node it
// means signed the bytes it has — not merely that some signature parses.
package node

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/luxfi/crypto"
)

// Purpose tags. Each is hashed once and placed first in its preimage, so the
// two statements occupy disjoint regions of the digest space.
const (
	tagAttest     = "hanzo.node.attest.v1"
	tagSuccession = "hanzo.node.succession.v1"
)

// ErrSignature reports a signature that is not a canonical secp256k1 signature
// over the digest by the address the statement names. The reasons are not
// distinguished: a verifier acts on all of them identically, and naming which
// check failed tells a forger which one to work on.
var ErrSignature = errors.New("node: signature does not verify against the statement")

// --- Fixed-width values -----------------------------------------------------
//
// Every value on this wire is a fixed-width byte array with one canonical
// 0x-hex spelling. Parsing happens once, at the edge, so a malformed address
// fails when JSON is decoded rather than silently producing a wrong digest
// later.

// Address is a 20-byte account address. It spells itself EIP-55 checksummed,
// which is the spelling the KMS stores and the fleet view shows.
type Address [20]byte

// Hash is a 32-byte keccak-256 digest.
type Hash [32]byte

// Measurement is the digest of the image a node key is bound to — the same
// 32-byte value and encoding as any other Hash, named for the role it plays.
type Measurement = Hash

// Signature is a 65-byte recoverable secp256k1 signature, r ‖ s ‖ v with
// v ∈ {0,1}.
type Signature [65]byte

// String returns the EIP-55 checksummed 0x-hex form. The checksum comes from
// the same routine that derives an address from a public key, so a record and
// its address always spell it identically.
func (a Address) String() string { return crypto.HexToAddress(hex.EncodeToString(a[:])).Hex() }

// String returns the 0x-hex form.
func (h Hash) String() string { return "0x" + hexOf(h[:]) }

// String returns the 0x-hex form.
func (s Signature) String() string { return "0x" + hexOf(s[:]) }

// hexOf is the one encoder every fixed-width value spells itself with.
func hexOf(b []byte) string { return hex.EncodeToString(b) }

// IsZero reports whether the address is unset.
func (a Address) IsZero() bool { return a == Address{} }

// IsZero reports whether the hash is unset.
func (h Hash) IsZero() bool { return h == Hash{} }

// ParseAddress decodes 20 bytes of hex, with or without the 0x prefix. It
// accepts any case and does not require a valid EIP-55 checksum, because a node
// operator types an address by hand; it always returns the checksummed form.
func ParseAddress(s string) (Address, error) {
	var a Address
	return a, decodeInto(a[:], s, "address")
}

// ParseHash decodes 32 bytes of hex, with or without the 0x prefix.
func ParseHash(s string) (Hash, error) {
	var h Hash
	return h, decodeInto(h[:], s, "hash")
}

// ParseMeasurement decodes 32 bytes of hex, with or without the 0x prefix.
func ParseMeasurement(s string) (Measurement, error) { return ParseHash(s) }

// ParseSignature decodes 65 bytes of hex, with or without the 0x prefix.
func ParseSignature(s string) (Signature, error) {
	var sig Signature
	return sig, decodeInto(sig[:], s, "signature")
}

// decodeInto fills dst from a hex string of exactly len(dst) bytes. It is the
// one decoder, so every fixed-width value accepts exactly the same spellings.
func decodeInto(dst []byte, s, what string) error {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil || len(raw) != len(dst) {
		return fmt.Errorf("node: %s must be %d bytes of hex", what, len(dst))
	}
	copy(dst, raw)
	return nil
}

func (a Address) MarshalJSON() ([]byte, error)   { return json.Marshal(a.String()) }
func (h Hash) MarshalJSON() ([]byte, error)      { return json.Marshal(h.String()) }
func (s Signature) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (a *Address) UnmarshalJSON(b []byte) error   { return unmarshal(b, a[:], "address") }
func (h *Hash) UnmarshalJSON(b []byte) error      { return unmarshal(b, h[:], "hash") }
func (s *Signature) UnmarshalJSON(b []byte) error { return unmarshal(b, s[:], "signature") }

func unmarshal(b, dst []byte, what string) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return decodeInto(dst, s, what)
}

// --- Statements -------------------------------------------------------------

// Attestation is the statement a node key signs about a boot payload: this
// address, running this image, at this epoch, attests these bytes.
//
// Payload is committed to as H(payload) and is never carried on the wire — the
// verifier already holds the bytes it wants checked, and echoing them back
// would invite verifying against the server's copy instead of its own.
type Attestation struct {
	Address     Address     `json:"address"`
	Measurement Measurement `json:"measurement"`
	Epoch       uint64      `json:"epoch"`
	Payload     []byte      `json:"-"`
}

// Digest returns the value the KMS signs for this attestation.
func (a Attestation) Digest() Hash {
	return hash(
		crypto.Keccak256([]byte(tagAttest)),
		a.Address[:],
		a.Measurement[:],
		epoch(a.Epoch),
		crypto.Keccak256(a.Payload),
	)
}

// Verify reports whether sig is a canonical signature over this statement by
// the address the statement names.
func (a Attestation) Verify(sig Signature) error { return verify(a.Digest(), sig, a.Address) }

// Succession is the statement an outgoing key signs to name its successor. It
// is what moves a stake from one address to the next: the settlement L1 checks
// it against the address it already knows, and no second authority is involved.
type Succession struct {
	Prev  Address `json:"prev"`
	Next  Address `json:"next"`
	Epoch uint64  `json:"epoch"`
}

// Digest returns the value the outgoing key signs for this succession.
func (s Succession) Digest() Hash {
	return hash(
		crypto.Keccak256([]byte(tagSuccession)),
		s.Prev[:],
		s.Next[:],
		epoch(s.Epoch),
	)
}

// Verify reports whether sig is a canonical signature over this succession by
// the outgoing address — the only address whose signature can hand the identity
// on.
func (s Succession) Verify(sig Signature) error { return verify(s.Digest(), sig, s.Prev) }

// --- Signed results ---------------------------------------------------------

// Receipt is what one signing request returns: the statement's public fields,
// the digest that was signed, and the signature over it. The payload stays with
// the caller, so verifying takes it as an argument.
type Receipt struct {
	Attestation
	Digest    Hash      `json:"digest"`
	Signature Signature `json:"signature"`
}

// Verify checks the receipt against the payload the caller holds: that the
// stated digest is the one this statement produces over those bytes, and that
// the signature over it recovers to the node the receipt names.
//
// Both halves matter. Checking the signature alone against the stated digest
// would prove only that some node signed something; recomputing the digest is
// what ties the signature to this payload, this image and this epoch.
func (r Receipt) Verify(payload []byte) error {
	a := r.Attestation
	a.Payload = payload
	if a.Digest() != r.Digest {
		return ErrSignature
	}
	return a.Verify(r.Signature)
}

// Handover is what one rotation returns: the succession and the outgoing key's
// signature over it. Unlike a Receipt it is self-contained, because a succession
// commits to nothing the verifier has to supply.
type Handover struct {
	Succession
	Digest    Hash      `json:"digest"`
	Signature Signature `json:"signature"`
}

// Verify checks that the stated digest is the one this succession produces and
// that the outgoing address signed it.
func (h Handover) Verify() error {
	if h.Succession.Digest() != h.Digest {
		return ErrSignature
	}
	return h.Succession.Verify(h.Signature)
}

// --- Recovery ---------------------------------------------------------------

// Recover returns the address whose key produced sig over d.
//
// The signature must be canonical: v ∈ {0,1}, r and s in range, and s in the
// lower half of the curve order. Rejecting high-s costs nothing here — the
// signer never produces one — and it means a signature has exactly one valid
// encoding, so a verifier that deduplicates by signature bytes cannot be shown
// the same statement twice under two spellings.
func Recover(d Hash, sig Signature) (Address, error) {
	v := sig[64]
	if v != 0 && v != 1 {
		return Address{}, ErrSignature
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if !crypto.ValidateSignatureValues(v, r, s, true) {
		return Address{}, ErrSignature
	}
	pub, err := crypto.SigToPub(d[:], sig[:])
	if err != nil || pub == nil {
		return Address{}, ErrSignature
	}
	return Address(crypto.PubkeyToAddress(*pub)), nil
}

// verify recovers and compares. The comparison is the whole check: a recovered
// address that is not the expected one is a signature by someone else.
func verify(d Hash, sig Signature, want Address) error {
	got, err := Recover(d, sig)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%w: signed by %s, want %s", ErrSignature, got, want)
	}
	return nil
}

func hash(parts ...[]byte) Hash {
	var h Hash
	copy(h[:], crypto.Keccak256(parts...))
	return h
}

func epoch(e uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], e)
	return b[:]
}
