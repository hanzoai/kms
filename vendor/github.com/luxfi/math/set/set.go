package set

import (
	"encoding/json"
	"sort"
)

// Set represents a set of unique elements
type Set[T comparable] map[T]struct{}

// Of creates a new set with the given elements
func Of[T comparable](elements ...T) Set[T] {
	s := make(Set[T], len(elements))
	for _, e := range elements {
		s[e] = struct{}{}
	}
	return s
}

// Add adds one or more elements to the set
// If the set is nil, this method will panic. Use NewSet() or Of() to create an initialized set.
func (s Set[T]) Add(elements ...T) {
	if s == nil {
		panic("set: Add called on nil Set - use NewSet() or Of() to create an initialized set")
	}
	for _, element := range elements {
		s[element] = struct{}{}
	}
}

// Contains checks if an element is in the set
func (s Set[T]) Contains(element T) bool {
	_, exists := s[element]
	return exists
}

// Remove removes an element from the set
func (s Set[T]) Remove(element T) {
	delete(s, element)
}

// Len returns the number of elements in the set
func (s Set[T]) Len() int {
	return len(s)
}

// List returns a slice of all elements in the set
func (s Set[T]) List() []T {
	result := make([]T, 0, len(s))
	for element := range s {
		result = append(result, element)
	}
	return result
}

// Clear removes all elements from the set
func (s Set[T]) Clear() {
	for k := range s {
		delete(s, k)
	}
}

// Union returns a new set containing all elements from both sets
func (s Set[T]) Union(other Set[T]) Set[T] {
	result := make(Set[T])
	for k := range s {
		result[k] = struct{}{}
	}
	for k := range other {
		result[k] = struct{}{}
	}
	return result
}

// Intersection returns a new set containing only elements in both sets
func (s Set[T]) Intersection(other Set[T]) Set[T] {
	result := make(Set[T])
	for k := range s {
		if other.Contains(k) {
			result[k] = struct{}{}
		}
	}
	return result
}

// Difference returns a new set containing elements in s but not in other
func (s Set[T]) Difference(other Set[T]) Set[T] {
	result := make(Set[T])
	for k := range s {
		if !other.Contains(k) {
			result[k] = struct{}{}
		}
	}
	return result
}

// Equals checks if two sets contain the same elements
func (s Set[T]) Equals(other Set[T]) bool {
	if len(s) != len(other) {
		return false
	}
	for k := range s {
		if !other.Contains(k) {
			return false
		}
	}
	return true
}

// Overlaps checks if two sets have any common elements
func (s Set[T]) Overlaps(other Set[T]) bool {
	for k := range s {
		if other.Contains(k) {
			return true
		}
	}
	return false
}

// Pop removes and returns an arbitrary element from the set
// Returns the element and true if the set was non-empty, otherwise returns zero value and false
func (s Set[T]) Pop() (T, bool) {
	for k := range s {
		delete(s, k)
		return k, true
	}
	var zero T
	return zero, false
}

// NewSet creates a new empty set with optional initial capacity
func NewSet[T comparable](capacity ...int) Set[T] {
	if len(capacity) > 0 && capacity[0] > 0 {
		return make(Set[T], capacity[0])
	}
	return make(Set[T])
}

// MarshalJSON implements json.Marshaler interface
// Marshals the set as a JSON array of elements in sorted order
func (s Set[T]) MarshalJSON() ([]byte, error) {
	// Convert set to slice for marshaling
	list := s.List()

	// Sort for consistent output (best effort for common types)
	if len(list) > 1 {
		switch any(list).(type) {
		case []int:
			sort.Ints(any(list).([]int))
		case []string:
			sort.Strings(any(list).([]string))
		case []float64:
			sort.Float64s(any(list).([]float64))
		}
	}

	return json.Marshal(list)
}

// UnmarshalJSON implements json.Unmarshaler interface
// Unmarshals a JSON array into a set, replacing existing contents
func (s *Set[T]) UnmarshalJSON(data []byte) error {
	var list []T
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	// Create a new set to replace existing contents
	*s = make(Set[T], len(list))

	// Add all elements from the list
	for _, element := range list {
		(*s)[element] = struct{}{}
	}

	return nil
}

// Peek returns a random element from the set.
// If the set is empty, returns the zero value and false.
func (s Set[T]) Peek() (T, bool) {
	for elt := range s {
		return elt, true
	}
	var zero T
	return zero, false
}
