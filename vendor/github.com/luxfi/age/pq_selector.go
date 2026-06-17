// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"fmt"
	"os"
)

// PQKemType selects between the two hybrid post-quantum KEMs that age
// supports. Both are first-class and produce distinct recipient prefixes:
//
//	age1pq1… → PQKemHPKEMLKEM768X25519  (HPKE RFC 9180 with MLKEM768-X25519)
//	age1xw1… → PQKemXWing                (IETF draft-connolly-cfrg-xwing-kem-10)
//
// At parse time the selection is automatic from the Bech32 prefix, so
// callers that already have a key string don't need to set this.
// PQKemType is only needed at *keygen* time when callers want to choose
// which KEM to produce.
type PQKemType string

const (
	// PQKemHPKEMLKEM768X25519 is the original post-quantum hybrid introduced
	// in age v1.3.0: HPKE (RFC 9180) with MLKEM768-X25519, HKDF-SHA256,
	// ChaCha20-Poly1305. Recipient prefix: age1pq1, identity prefix:
	// AGE-SECRET-KEY-PQ-1.
	PQKemHPKEMLKEM768X25519 PQKemType = "hpke-mlkem768x25519"

	// PQKemXWing is the X-Wing KEM per IETF draft-connolly-cfrg-xwing-kem-10.
	// Simpler combiner (SHA3-256 direct) with the 6-byte XWingLabel, smaller
	// proof surface, HPKE KEM codepoint 25722. Recipient prefix: age1xw1,
	// identity prefix: AGE-SECRET-KEY-XW-1.
	PQKemXWing PQKemType = "xwing"

	// DefaultPQKemEnv is the environment variable consulted by
	// [GeneratePQIdentity] when callers pass an empty PQKemType.
	DefaultPQKemEnv = "AGE_PQ_KEM"
)

// resolvePQKem returns the effective KEM type, consulting the env var when
// the caller didn't specify one. Defaults to X-Wing for new keys because
// the IETF draft is the recommended future direction (smaller combiner,
// simpler binding analysis, assigned HPKE codepoint).
func resolvePQKem(kem PQKemType) PQKemType {
	if kem != "" {
		return kem
	}
	if v := PQKemType(os.Getenv(DefaultPQKemEnv)); v != "" {
		return v
	}
	return PQKemXWing
}

// GeneratePQIdentity generates a new post-quantum hybrid identity using the
// selected KEM. If kem is empty, the AGE_PQ_KEM environment variable is
// consulted; if that is also unset, X-Wing is used.
//
// The returned [Identity] is either an [*XWingIdentity] or a
// [*HybridIdentity]; callers can type-assert if they need KEM-specific
// methods, but usually the generic [Identity] interface is sufficient.
//
// Example:
//
//	id, err := age.GeneratePQIdentity(age.PQKemXWing)
//	if err != nil { … }
//	fmt.Println(id.(interface{ Recipient() Recipient }).Recipient())
func GeneratePQIdentity(kem PQKemType) (Identity, error) {
	switch resolvePQKem(kem) {
	case PQKemXWing:
		return GenerateXWingIdentity()
	case PQKemHPKEMLKEM768X25519:
		return GenerateHybridIdentity()
	default:
		return nil, fmt.Errorf("age: unknown PQ KEM %q (valid: %s, %s)",
			kem, PQKemXWing, PQKemHPKEMLKEM768X25519)
	}
}

// SupportedPQKems returns the list of post-quantum KEM types supported by
// this build of age. Useful for CLIs that enumerate options.
func SupportedPQKems() []PQKemType {
	return []PQKemType{PQKemXWing, PQKemHPKEMLKEM768X25519}
}
