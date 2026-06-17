// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package lru

import (
	"container/list"
	"sync"

	"github.com/luxfi/cache"
)

// SizedCache is an LRU cache bounded by total size rather than entry count.
type SizedCache[K comparable, V any] struct {
	mu          sync.Mutex
	maxSize     int
	currentSize int
	sizeFn      func(K, V) int
	items       map[K]*list.Element
	lru         *list.List
}

type sizedEntry[K comparable, V any] struct {
	key   K
	value V
	size  int
}

// NewSizedCache creates a size-bounded LRU cache.
func NewSizedCache[K comparable, V any](maxSize int, sizeFn func(K, V) int) *SizedCache[K, V] {
	if maxSize <= 0 {
		maxSize = 1
	}
	if sizeFn == nil {
		sizeFn = func(K, V) int { return 1 }
	}
	return &SizedCache[K, V]{
		maxSize: maxSize,
		sizeFn:  sizeFn,
		items:   make(map[K]*list.Element),
		lru:     list.New(),
	}
}

// Put inserts or replaces a value.
func (c *SizedCache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entrySize := c.sizeFn(key, value)
	if entrySize > c.maxSize {
		c.flushLocked()
		return
	}

	if elem, ok := c.items[key]; ok {
		oldEntry := elem.Value.(*sizedEntry[K, V])
		c.currentSize -= oldEntry.size
		c.lru.Remove(elem)
		delete(c.items, key)
	}

	for c.currentSize > c.maxSize-entrySize {
		back := c.lru.Back()
		if back == nil {
			break
		}
		oldEntry := back.Value.(*sizedEntry[K, V])
		c.currentSize -= oldEntry.size
		delete(c.items, oldEntry.key)
		c.lru.Remove(back)
	}

	e := &sizedEntry[K, V]{key: key, value: value, size: entrySize}
	c.items[key] = c.lru.PushFront(e)
	c.currentSize += entrySize
}

// Get retrieves a value and marks it as most recently used.
func (c *SizedCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.lru.MoveToFront(elem)
		return elem.Value.(*sizedEntry[K, V]).value, true
	}
	var zero V
	return zero, false
}

// Evict removes a key from the cache.
func (c *SizedCache[K, V]) Evict(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*sizedEntry[K, V])
		c.currentSize -= entry.size
		delete(c.items, key)
		c.lru.Remove(elem)
	}
}

// Flush removes all entries.
func (c *SizedCache[K, V]) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushLocked()
}

func (c *SizedCache[K, V]) flushLocked() {
	c.items = make(map[K]*list.Element)
	c.lru.Init()
	c.currentSize = 0
}

// Len returns number of entries.
func (c *SizedCache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// PortionFilled returns the ratio of size used to max size.
func (c *SizedCache[K, V]) PortionFilled() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maxSize == 0 {
		return 0
	}
	return float64(c.currentSize) / float64(c.maxSize)
}

var _ cache.Cacher[struct{}, struct{}] = (*SizedCache[struct{}, struct{}])(nil)
