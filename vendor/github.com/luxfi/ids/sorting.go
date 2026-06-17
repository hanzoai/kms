// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ids

import (
	"bytes"
	"cmp"
	"slices"
)

// Sort sorts a slice of Sortable elements using their Compare method.
func Sort[T Sortable[T]](s []T) {
	slices.SortFunc(s, T.Compare)
}

// IsSorted returns true iff the elements in [s] are sorted.
func IsSorted[T Sortable[T]](s []T) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i].Compare(s[i+1]) > 0 {
			return false
		}
	}
	return true
}

// IsSortedAndUnique returns true iff the elements in [s] are sorted and unique.
func IsSortedAndUnique[T Sortable[T]](s []T) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i].Compare(s[i+1]) >= 0 {
			return false
		}
	}
	return true
}

// IsSortedAndUniqueOrdered returns true iff the elements in [s] are sorted and unique.
// Uses cmp.Ordered constraint for built-in comparable types.
func IsSortedAndUniqueOrdered[T cmp.Ordered](s []T) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i] >= s[i+1] {
			return false
		}
	}
	return true
}

// IsSortedBytes returns true iff the byte slices in [s] are sorted.
func IsSortedBytes[T ~[]byte](s []T) bool {
	for i := 0; i < len(s)-1; i++ {
		if bytes.Compare(s[i], s[i+1]) > 0 {
			return false
		}
	}
	return true
}

// IsSortedAndUniqueBytes returns true iff the byte slices in [s] are sorted and unique.
func IsSortedAndUniqueBytes[T ~[]byte](s []T) bool {
	for i := 0; i < len(s)-1; i++ {
		if bytes.Compare(s[i], s[i+1]) >= 0 {
			return false
		}
	}
	return true
}
