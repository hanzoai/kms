// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package store

import "fmt"

// Key prefix schema for ZapDB.
//
// Layout:
//
//	org/<slug>/secret/<key>   — encrypted secret blobs
//	org/<slug>/shard          — this node's Shamir shard for the org
//	org/<slug>/meta/<key>     — FHE-encrypted metadata
//	org/<slug>/crdt/<seq>     — CRDT operation log (FHE-encrypted ops)

const (
	prefixOrg    = "org/"
	prefixSecret = "/secret/"
	prefixShard  = "/shard"
	prefixMeta   = "/meta/"
	prefixCRDT   = "/crdt/"
)

// SecretKey returns the ZapDB key for an encrypted secret.
func SecretKey(orgSlug, key string) []byte {
	return []byte(fmt.Sprintf("%s%s%s%s", prefixOrg, orgSlug, prefixSecret, key))
}

// ShardKey returns the ZapDB key for this node's shard for an org.
func ShardKey(orgSlug string) []byte {
	return []byte(fmt.Sprintf("%s%s%s", prefixOrg, orgSlug, prefixShard))
}

// MetaKey returns the ZapDB key for FHE-encrypted metadata.
func MetaKey(orgSlug, key string) []byte {
	return []byte(fmt.Sprintf("%s%s%s%s", prefixOrg, orgSlug, prefixMeta, key))
}

// CRDTKey returns the ZapDB key for a CRDT operation at the given sequence.
func CRDTKey(orgSlug string, seq uint64) []byte {
	return []byte(fmt.Sprintf("%s%s%s%016x", prefixOrg, orgSlug, prefixCRDT, seq))
}

// SecretPrefix returns the prefix for listing all secrets in an org.
func SecretPrefix(orgSlug string) []byte {
	return []byte(fmt.Sprintf("%s%s%s", prefixOrg, orgSlug, prefixSecret))
}

// CRDTPrefix returns the prefix for listing all CRDT ops in an org.
func CRDTPrefix(orgSlug string) []byte {
	return []byte(fmt.Sprintf("%s%s%s", prefixOrg, orgSlug, prefixCRDT))
}
