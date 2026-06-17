// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package cache

import (
	"sync"

	"github.com/luxfi/metric"
)

// DualMapCache is a simple two-map cache placeholder with migration hooks.
// The implementation is intentionally minimal to preserve API compatibility.
type DualMapCache[K comparable, V any] struct {
	mu    sync.RWMutex
	items map[K]V
}

// NewDualMapCache creates a new DualMapCache. Metrics are optional.
func NewDualMapCache[K comparable, V any](_ metric.Registry) *DualMapCache[K, V] {
	return &DualMapCache[K, V]{
		items: make(map[K]V),
	}
}

// Put inserts or replaces an element in the cache.
func (c *DualMapCache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = value
}

// Get returns the entry with the key, if it exists.
func (c *DualMapCache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.items[key]
	return val, ok
}

// Evict removes the specified entry from the cache.
func (c *DualMapCache[K, V]) Evict(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// Flush removes all entries from the cache.
func (c *DualMapCache[K, V]) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[K]V)
}

// Len returns the number of elements in the cache.
func (c *DualMapCache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// PortionFilled returns fraction of cache currently filled.
func (c *DualMapCache[K, V]) PortionFilled() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.items) == 0 {
		return 0
	}
	return 1
}

// Migrate is a no-op placeholder for dual-map cache migration.
func (c *DualMapCache[K, V]) Migrate() {}
