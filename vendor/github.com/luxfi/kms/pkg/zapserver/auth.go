// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// auth.go — envelope-signature verification for ZAP secret opcodes.
//
// The envelope shape lives in pkg/envelope so the client and server
// share one source of truth for the wire format. This file is a thin
// re-export so package consumers don't need to know about the split.
//
// Every secret-opcode request rides an Envelope: the JSON payload plus
// the signer's typed NodeID + 48-byte commitment + ML-DSA-65
// signature. The verifier:
//
//  1. Parses the envelope from the inbound frame.
//  2. Reconstructs the signed digest from (path, name, env, op,
//     timestamp, nonce) and verifies the signature against the
//     envelope's bound public key.
//  3. Returns the verified Identity to the dispatcher; authorization
//     (consensus-native) runs separately.
//
// There is NO ACL. Authority lives in consensus (consensus_auth.go).
// If the envelope is missing or fails verification, the request is
// rejected at the wire layer with statusForbid.

package zapserver

import (
	"encoding/json"
	"time"

	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/envelope"
)

// Envelope re-exports the canonical wire shape.
type Envelope = envelope.Envelope

// EnvelopeIdentity re-exports the inner identity block.
type EnvelopeIdentity = envelope.Identity

// EnvelopeVersion re-exports the canonical version constant.
const EnvelopeVersion = envelope.Version

// EnvelopeMaxClockSkew re-exports the canonical freshness window.
const EnvelopeMaxClockSkew = envelope.MaxClockSkew

// ParseEnvelope re-exports envelope.Parse.
func ParseEnvelope(raw []byte) (*Envelope, error) {
	return envelope.Parse(raw)
}

// VerifyEnvelope re-exports envelope.Verify and converts the typed
// result into the local Identity shape that the consensus authorizer
// understands. The signature is verified via luxfi/keys (the canonical
// service-envelope verifier).
func VerifyEnvelope(env *Envelope, now time.Time) (Identity, error) {
	v, err := envelope.Verify(env, now, keys.VerifyServiceEnvelope)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		NodeID:      v.NodeID,
		FullDigest:  v.FullDigest,
		ServicePath: v.ServicePath,
	}, nil
}

// BuildEnvelope is the canonical helper for callers that hold a
// *keys.ServiceIdentity. Lifts the public identity into the envelope
// header and delegates to envelope.Build.
func BuildEnvelope(ident *keys.ServiceIdentity, op uint16, req json.RawMessage, nonce string, now time.Time) (*Envelope, error) {
	hdr := envelope.IdentityHeader{
		NodeID:      ident.NodeID,
		FullDigest:  ident.FullDigest,
		ServicePath: ident.ServicePath,
		PublicKey:   ident.PublicKey,
	}
	return envelope.Build(hdr, ident, op, req, nonce, now)
}
