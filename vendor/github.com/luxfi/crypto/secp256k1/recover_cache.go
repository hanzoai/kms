// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1

import (
	"github.com/luxfi/cache/lru"
)

// RecoverCacheType provides a cache for public key recovery with methods
type RecoverCacheType struct {
	cache *lru.Cache[string, *PublicKey]
}

// NewRecoverCache creates a new recover cache
func NewRecoverCache(size int) RecoverCacheType {
	return RecoverCacheType{
		cache: lru.NewCache[string, *PublicKey](size),
	}
}

// RecoverPublicKey recovers a public key from a message and signature
func (r RecoverCacheType) RecoverPublicKey(msg, sig []byte) (*PublicKey, error) {
	return RecoverPublicKey(msg, sig)
}

// RecoverPublicKeyFromHash recovers a public key from a hash and signature
func (r RecoverCacheType) RecoverPublicKeyFromHash(hash, sig []byte) (*PublicKey, error) {
	// Check cache first
	cacheKey := string(hash) + string(sig)
	if cached, found := r.cache.Get(cacheKey); found {
		return cached, nil
	}

	// Recover the public key
	pk, err := RecoverPublicKeyFromHash(hash, sig)
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.cache.Put(cacheKey, pk)
	return pk, nil
}
