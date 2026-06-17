//go:build !metrics

// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

func init() {
	DefaultRegistry = NewNoOpRegistry()
	defaultFactory = NewNoOpFactory()
}
