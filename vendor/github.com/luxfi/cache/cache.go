// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cache provides caching interfaces and implementations.
package cache

// Cacher acts as a best effort key value store.
type Cacher[K comparable, V any] interface {
	// Put inserts an element into the cache.
	Put(key K, value V)

	// Get returns the entry with the key, if it exists.
	Get(key K) (V, bool)

	// Evict removes the specified entry from the cache.
	Evict(key K)

	// Flush removes all entries from the cache.
	Flush()

	// Len returns the number of elements in the cache.
	Len() int

	// PortionFilled returns fraction of cache currently filled (0 --> 1).
	PortionFilled() float64
}
