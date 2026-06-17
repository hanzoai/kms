// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package container provides LRU cache implementation
package container

import "container/list"

// LRUCache implements least-recently-used cache
type LRUCache[K comparable, V any] struct {
	capacity int
	elements map[K]*list.Element
	lru      *list.List
}

// NewLRUCache creates a new LRU cache
type cacheEntry[K comparable, V any] struct {
	key   K
	value V
}

func NewLRUCache[K comparable, V any](size int) *LRUCache[K, V] {
	return &LRUCache[K, V]{
		capacity: size,
		elements: make(map[K]*list.Element),
		lru:      list.New(),
	}
}

func NewLRUCacheWithOnEvict[K comparable, V any](size int, onEvict func(K, V)) *LRUCache[K, V] {
	return &LRUCache[K, V]{
		capacity: size,
		elements: make(map[K]*list.Element),
		lru:      list.New(),
	}
}

func (c *LRUCache[K, V]) Get(key K) (V, bool) {
	if elem, exists := c.elements[key]; exists {
		c.lru.MoveToFront(elem)
		return elem.Value.(*cacheEntry[K, V]).value, true
	}
	var zero V
	return zero, false
}

func (c *LRUCache[K, V]) Put(key K, value V) {
	if elem, exists := c.elements[key]; exists {
		c.lru.MoveToFront(elem)
		elem.Value.(*cacheEntry[K, V]).value = value
		return
	}
	
	if len(c.elements) >= c.capacity {
		back := c.lru.Back()
		if back != nil {
			c.lru.Remove(back)
			delete(c.elements, back.Value.(*cacheEntry[K, V]).key)
		}
	}
	
	elem := c.lru.PushFront(&cacheEntry[K, V]{key, value})
	c.elements[key] = elem
}

func (c *LRUCache[K, V]) Delete(key K) {
	if elem, exists := c.elements[key]; exists {
		c.lru.Remove(elem)
		delete(c.elements, key)
	}
}

func (c *LRUCache[K, V]) Len() int {
	return len(c.elements)
}

func (c *LRUCache[K, V]) Evict(key K) {
	c.Delete(key)
}