// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package math

import "bytes"

// IsSortedBytes returns true if s is sorted in ascending order.
func IsSortedBytes[T ~[]byte](s []T) bool {
	for i := 0; i < len(s)-1; i++ {
		if bytes.Compare(s[i], s[i+1]) == 1 {
			return false
		}
	}
	return true
}
