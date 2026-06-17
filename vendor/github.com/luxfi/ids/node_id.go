// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ids

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/hash"
)

const (
	NodeIDPrefix = "NodeID-"
	NodeIDLen    = ShortIDLen
)

var (
	EmptyNodeID = NodeID{}

	errShortNodeID = errors.New("insufficient NodeID length")

	_ Sortable[NodeID] = NodeID{}
)

type NodeID ShortID

func (id NodeID) String() string {
	return ShortID(id).PrefixedString(NodeIDPrefix)
}

func (id NodeID) Bytes() []byte {
	return id[:]
}

func (id NodeID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + id.String() + `"`), nil
}

func (id NodeID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

func (id *NodeID) UnmarshalJSON(b []byte) error {
	str := string(b)
	if str == nullStr { // If "null", do nothing
		return nil
	} else if len(str) <= 2+len(NodeIDPrefix) {
		return fmt.Errorf("%w: expected to be > %d", errShortNodeID, 2+len(NodeIDPrefix))
	}

	lastIndex := len(str) - 1
	if str[0] != '"' || str[lastIndex] != '"' {
		return errMissingQuotes
	}

	var err error
	*id, err = NodeIDFromString(str[1:lastIndex])
	return err
}

func (id *NodeID) UnmarshalText(text []byte) error {
	return id.UnmarshalJSON(text)
}

func (id NodeID) Compare(other NodeID) int {
	return bytes.Compare(id[:], other[:])
}

// ToNodeID attempt to convert a byte slice into a node id
func ToNodeID(bytes []byte) (NodeID, error) {
	nodeID, err := ToShortID(bytes)
	return NodeID(nodeID), err
}

func NodeIDFromCert(cert *Certificate) NodeID {
	return hash.ComputeHash160Array(
		hash.ComputeHash256(cert.Raw),
	)
}

// NodeIDFromString is the inverse of NodeID.String()
func NodeIDFromString(nodeIDStr string) (NodeID, error) {
	asShort, err := ShortFromPrefixedString(nodeIDStr, NodeIDPrefix)
	if err != nil {
		return NodeID{}, err
	}
	return NodeID(asShort), nil
}

// NodeIDPrefix for the legacy ML-DSA NodeID derivation. Retained for
// backwards compatibility with chains that registered validators under the
// pre-v1 derivation; new strict-PQ chains use the canonical SHAKE256-384
// derivation in node_id_scheme.go (NodeIDScheme.DeriveMLDSA), which
// domain-separates by chain id AND scheme byte and produces a 48-byte
// commitment whose 20-byte prefix is the NodeID.
const NodeIDMLDSADomainPrefix = "LuxNodeID/v1"

// NodeIDFromMLDSA derives a 20-byte NodeID from an ML-DSA public key
// using the legacy (pre-chain-binding) derivation. Kept stable for
// existing call sites; new strict-PQ chains MUST use
// NodeIDScheme.DeriveMLDSA or TypedNodeIDFromMLDSA, which bind the
// chain id and scheme byte into the digest and return the full
// 48-byte SHAKE256-384 commitment alongside the truncated NodeID.
//
// NodeID = RIPEMD160(SHA256("LuxNodeID/v1" || mldsa_pubkey_bytes))
func NodeIDFromMLDSA(mldsaPubKey []byte) NodeID {
	prefix := []byte(NodeIDMLDSADomainPrefix)
	data := make([]byte, len(prefix)+len(mldsaPubKey))
	copy(data, prefix)
	copy(data[len(prefix):], mldsaPubKey)
	return hash.ComputeHash160Array(hash.ComputeHash256(data))
}
