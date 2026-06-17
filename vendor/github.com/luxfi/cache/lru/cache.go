// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package lru provides the ONE standard LRU cache implementation using container package.
package lru

import (
	"sync"

	"github.com/luxfi/cache"
	"github.com/luxfi/container"
)

// Cache is the standard LRU cache - ONE implementation, no duplicates
type Cache[K comparable, V any] struct {
	mu             sync.Mutex
	containerCache container.Cache[K, V] // Uses container package internally
	capacity       int
	onEvict        func(K, V)
}

// NewCache creates a new LRU cache - THE standard way
func NewCache[K comparable, V any](size int) *Cache[K, V] {
	if size <= 0 {
		size = 1
	}
	return &Cache[K, V]{
		containerCache: container.NewLRUCache[K, V](size),
		capacity:       size,
		onEvict:        nil,
	}
}

// NewCacheWithOnEvict creates cache with eviction callback
func NewCacheWithOnEvict[K comparable, V any](size int, onEvict func(K, V)) *Cache[K, V] {
	if size <= 0 {
		size = 1
	}
	return &Cache[K, V]{
		containerCache: container.NewLRUCacheWithOnEvict[K, V](size, onEvict),
		capacity:       size,
		onEvict:        onEvict,
	}
}

// Get retrieves value from cache
func (c *Cache[K, V]) Get(key K) (value V, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.containerCache.Get(key)
}

// Put adds value to cache
func (c *Cache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.containerCache.Put(key, value)
}

// Delete removes value from cache
func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.containerCache.Delete(key)
}

// Len returns cache size
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.containerCache.Len()
}

// Clear removes all items
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.containerCache = container.NewLRUCache[K, V](c.capacity)
}

// Contains checks key existence
func (c *Cache[K, V]) Contains(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.containerCache.Get(key)
	return ok
}

// Size returns cache size
func (c *Cache[K, V]) Size() int {
	return c.Len()
}

// Evict removes a key from cache (required by Cacher interface)
func (c *Cache[K, V]) Evict(key K) {
	c.Delete(key)
}

// Flush removes all entries from cache (required by Cacher interface)
func (c *Cache[K, V]) Flush() {
	c.Clear()
}

// PortionFilled returns fraction of cache currently filled (0 --> 1)
func (c *Cache[K, V]) PortionFilled() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	current := float64(c.containerCache.Len())
	capacity := float64(c.capacity)
	if capacity == 0 {
		return 0
	}
	return current / capacity
}

// Interface compliance
var _ cache.Cacher[struct{}, struct{}] = (*Cache[struct{}, struct{}])(nil)
