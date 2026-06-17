//go:build metrics

// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

// NewRegistry returns a new in-process registry.
func NewRegistry() Registry {
	return newRegistry()
}
