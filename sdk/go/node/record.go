package node

import (
	"encoding/json"
	"strings"
	"time"
)

// PublicKey is an uncompressed secp256k1 public key, 0x04 ‖ X ‖ Y. A record
// publishes one so a reader can confirm the address derives from it without
// asking the KMS to vouch for its own answer.
type PublicKey [65]byte

// String returns the 0x-hex form.
func (p PublicKey) String() string { return "0x" + hexOf(p[:]) }

// ParsePublicKey decodes 65 bytes of hex, with or without the 0x prefix.
func ParsePublicKey(s string) (PublicKey, error) {
	var p PublicKey
	return p, decodeInto(p[:], s, "public key")
}

func (p PublicKey) MarshalJSON() ([]byte, error) { return json.Marshal(p.String()) }
func (p *PublicKey) UnmarshalJSON(b []byte) error {
	return unmarshal(b, p[:], "public key")
}

// TEE names a CPU trusted execution environment family. The vocabulary matches
// the attestation package the KMS gates epoch keys with, spelled out, because
// this value is read by people in a fleet listing and written by the node daemon
// in a request body.
type TEE string

const (
	// None: no CPU TEE. The measurement is declared by the node.
	None TEE = "none"
	// SevSnp, Tdx and Sgx are hardware families. Naming one obliges the caller
	// to supply a report the KMS can check against the vendor's root.
	SevSnp TEE = "sev-snp"
	Tdx    TEE = "tdx"
	Sgx    TEE = "sgx"
)

// UnmarshalJSON accepts a family name in any case, with surrounding space. The
// vocabulary is lower case; normalising here rather than at each boundary means
// the client, the server and the stored record all hold one spelling, and a
// daemon that writes "SEV-SNP" is not refused for a difference that carries no
// meaning.
func (t *TEE) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*t = TEE(strings.ToLower(strings.TrimSpace(s)))
	return nil
}

// Known reports whether t is a family this protocol defines. An empty TEE reads
// as None and is known.
func (t TEE) Known() bool {
	switch t {
	case "", None, SevSnp, Tdx, Sgx:
		return true
	}
	return false
}

// Hardware reports whether t names a CPU TEE, and so whether a report has to
// back the measurement before it means anything.
func (t TEE) Hardware() bool { return t.Known() && t != "" && t != None }

// Evidence is what a node presents to say which image it is running. It
// accompanies every request that touches key material, because the measurement
// is the associated data the key is sealed under: without it the key does not
// open.
type Evidence struct {
	// TEE names the family that produced Measurement. Empty reads as None.
	TEE TEE `json:"tee"`
	// Measurement is the image digest the key is bound to.
	Measurement Measurement `json:"measurement"`
	// Quote is the hardware attestation report backing Measurement. It belongs
	// only with a hardware family; supplying one under None is a contradiction.
	Quote []byte `json:"quote,omitempty"`
}

// Declare returns evidence for an image digest on hardware with no CPU TEE,
// which is what a host running the microVM under the Virtualization framework,
// or on an x86-64 or arm64 host without SEV-SNP or TDX, presents today.
func Declare(m Measurement) Evidence { return Evidence{TEE: None, Measurement: m} }

// Status is a node identity's lifecycle state. Only an active identity signs.
type Status string

const (
	// Active: the key is sealed, usable, and is the node's current identity.
	Active Status = "active"
	// Superseded: rotated. The record carries the succession its predecessor
	// signed; its material is destroyed, so it can never sign again.
	Superseded Status = "superseded"
	// Revoked: decommissioned or slashed. Material destroyed, signing refused
	// permanently. The record survives so the fleet history and the address stay
	// enumerable and the settlement L1 can attribute a slash.
	Revoked Status = "revoked"
)

// Record is what the KMS knows about one node identity.
//
// It carries no key material and has no field for any: the sealed private key
// lives under a different store key entirely, so no serialization of this type
// can leak one.
type Record struct {
	// Address is the wallet, and so the node's identity everywhere: on the
	// settlement L1, in the staking account, in the reward account, and in the
	// fleet view.
	Address Address `json:"address"`
	// Org is the tenant that operates the node. A Hanzo-owned node and a third
	// party's node differ only in this field.
	Org string `json:"org"`
	// Subject is the IAM subject the identity was enrolled to — the only
	// principal that may sign with it.
	Subject string `json:"subject"`
	// PublicKey is the address's uncompressed public key.
	PublicKey PublicKey `json:"public_key"`
	// Measurement is the image the key is sealed to and usable from.
	Measurement Measurement `json:"measurement"`
	// TEE is the family that produced Measurement.
	TEE TEE `json:"tee"`
	// Attested reports whether hardware produced Measurement. False means the
	// node declared it: the key is still pinned to that one image, but the value
	// is the node's own claim.
	Attested bool `json:"attested"`
	// Status is the lifecycle state.
	Status Status `json:"status"`
	// Epoch is the last epoch this identity signed at. The next signature must
	// exceed it.
	Epoch uint64 `json:"epoch"`
	// Prev and Next link a rotation chain. Nil at either end.
	Prev *Address `json:"prev,omitempty"`
	Next *Address `json:"next,omitempty"`
	// Succession is the statement this identity signed to hand itself on,
	// present on a superseded record. It is what the settlement L1 reads to move
	// the stake, and it stays readable after the key is gone.
	Succession *Handover `json:"succession,omitempty"`
	// Reason records why an identity was revoked.
	Reason string `json:"reason,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Fleet is a tenant's node identities. Truncated reports that the fleet exceeded
// what one listing returns and Nodes is a bounded prefix, so a caller never
// mistakes a capped answer for the whole fleet.
type Fleet struct {
	Nodes     []*Record `json:"nodes"`
	Truncated bool      `json:"truncated"`
}
