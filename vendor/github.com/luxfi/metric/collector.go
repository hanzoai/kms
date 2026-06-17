// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

// Collector is a marker interface for compatibility with Registerer.
type Collector interface{}

// AsCollector returns a metric as a Collector for registration.
// Registration is a no-op for high-perf metrics, so this function simply
// returns the input value.
func AsCollector(v interface{}) Collector {
	return v
}
