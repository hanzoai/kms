// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// identity.go — mnemonic-derived service identity for kmsclient.
//
// Every kmsclient call over ZAP is signed by an Identity. The Identity
// is derived from a BIP-39 mnemonic + a service path via the canonical
// luxfi/keys.NewServiceIdentity surface. The mnemonic lives in a k8s
// Secret managed by the kms-operator; the service reads it at boot
// from the LUX_MNEMONIC env var (set on the Pod via the secret),
// derives its Identity, and uses it for the lifetime of the process.
//
// One mnemonic per service deployment. One identity per (mnemonic,
// path). Same path on a fresh pod → same NodeID byte-for-byte — the
// scale-out story is: register the path once with consensus, every
// replica auto-shares the identity.
//
// kmsclient also re-exports the underlying *keys.ServiceIdentity so
// callers that already manage a ServiceIdentity (e.g. the kms-operator
// reading its own mnemonic from the k8s API) can drop it straight
// into Config.Identity.

package kmsclient

import (
	"errors"
	"os"
	"strings"

	"github.com/luxfi/keys"
	"github.com/luxfi/kms/pkg/envelope"
)

// Identity is the per-service signing key + canonical NodeID. Built
// from a BIP-39 mnemonic and a service path. Carries the public
// envelope header so the kmsclient can stamp it onto every outbound
// request.
//
// Safe for concurrent use after construction.
type Identity struct {
	// ServiceIdentity is the canonical luxfi/keys identity. Exposed
	// so callers that need to sign envelopes outside the kmsclient
	// surface (e.g. a cross-service RPC) can reuse it.
	*keys.ServiceIdentity

	// Header is the public block kmsclient stamps onto every envelope.
	Header envelope.IdentityHeader
}

// NewIdentity is the canonical constructor. mnemonic must be a valid
// BIP-39 phrase; servicePath identifies the service (e.g.
// "hanzo/kms-operator", "hanzo/commerce"). Same input → same NodeID.
func NewIdentity(mnemonic, servicePath string) (*Identity, error) {
	si, err := keys.NewServiceIdentity(mnemonic, servicePath)
	if err != nil {
		return nil, err
	}
	return &Identity{
		ServiceIdentity: si,
		Header: envelope.IdentityHeader{
			NodeID:      si.NodeID,
			FullDigest:  si.FullDigest,
			ServicePath: si.ServicePath,
			PublicKey:   si.PublicKey,
		},
	}, nil
}

// IdentityFromEnv reads LUX_MNEMONIC (or MNEMONIC as a fallback) and
// derives an Identity at the given servicePath. Used by services that
// receive their mnemonic via a k8s Secret mounted as an env var.
//
// Returns an error when neither env var is set; the caller MUST fail
// closed (the consensus-native ZAP path is not reachable without an
// identity).
func IdentityFromEnv(servicePath string) (*Identity, error) {
	mnemonic := strings.TrimSpace(firstNonEmptyEnv("LUX_MNEMONIC", "MNEMONIC"))
	if mnemonic == "" {
		return nil, errors.New("kmsclient: LUX_MNEMONIC (or MNEMONIC) is not set")
	}
	return NewIdentity(mnemonic, servicePath)
}

// Wipe zeroes the underlying private key. Idempotent.
func (i *Identity) Wipe() {
	if i == nil {
		return
	}
	if i.ServiceIdentity != nil {
		i.ServiceIdentity.Wipe()
	}
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}
