// Copyright (C) 2019-2024, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package math

import (
	"github.com/luxfi/math/heap"
)

// AveragerHeap maintains a heap of the averagers keyed by a comparable type.
// K is the key type (e.g., ids.NodeID).
type AveragerHeap[K comparable] interface {
	// Add the average to the heap. If key is already in the heap, the
	// average will be replaced and the old average will be returned. If there
	// was not an old average, false will be returned.
	Add(key K, averager Averager) (Averager, bool)
	// Remove attempts to remove the average that was added with the provided
	// key, if none is contained in the heap, [false] will be returned.
	Remove(key K) (Averager, bool)
	// Pop attempts to remove the node with either the largest or smallest
	// average, depending on if this is a max heap or a min heap, respectively.
	Pop() (K, Averager, bool)
	// Peek attempts to return the node with either the largest or smallest
	// average, depending on if this is a max heap or a min heap, respectively.
	Peek() (K, Averager, bool)
	// Len returns the number of nodes that are currently in the heap.
	Len() int
}

type averagerHeap[K comparable] struct {
	heap heap.Map[K, Averager]
}

// NewMaxAveragerHeap returns a new empty max heap. The returned heap is not
// thread safe.
func NewMaxAveragerHeap[K comparable]() AveragerHeap[K] {
	return averagerHeap[K]{
		heap: heap.NewMap[K, Averager](func(a, b Averager) bool {
			return a.Read() > b.Read()
		}),
	}
}

func (h averagerHeap[K]) Add(key K, averager Averager) (Averager, bool) {
	return h.heap.Push(key, averager)
}

func (h averagerHeap[K]) Remove(key K) (Averager, bool) {
	return h.heap.Remove(key)
}

func (h averagerHeap[K]) Pop() (K, Averager, bool) {
	return h.heap.Pop()
}

func (h averagerHeap[K]) Peek() (K, Averager, bool) {
	return h.heap.Peek()
}

func (h averagerHeap[K]) Len() int {
	return h.heap.Len()
}
