// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package container provides core container interfaces and implementations
package container

// List interface for sequential data
type List[T any] interface {
	Front() interface{}
	Back() interface{}
	PushFront(T)
	PushBack(T)
	Remove(interface{})
	Len() int
}

// Map interface for key-value storage
type Map[K comparable, V any] interface {
	Put(K, V)
	Get(K) (V, bool)
	Delete(K)
	Len() int
	Oldest() (K, V, bool)
	Clear()
}

// Cache interface for size-bounded storage
type Cache[K comparable, V any] interface {
	Put(K, V)
	Get(K) (V, bool)
	Delete(K)
	Len() int
	Evict(K)
}