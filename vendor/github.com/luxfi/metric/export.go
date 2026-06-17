// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"net/http"
)

// Export types needed by the node.

// ProcessCollectorOpts are options for the process collector
type ProcessCollectorOpts struct {
	Namespace string
	PidFn     func() (int, error)
}

// MetricDesc describes a metric.
type MetricDesc struct {
	Name string
	Help string
	Type MetricType
}

// NewProcessCollector creates a new process collector (no-op for now).
func NewProcessCollector(opts ProcessCollectorOpts) Collector {
	return &processCollector{opts: opts}
}

// NewGoCollector creates a new Go collector (no-op for now).
func NewGoCollector() Collector {
	return &goCollector{}
}

// MetricFamilies is a slice of metric families.
type MetricFamilies = []*MetricFamily

// NewHTTPHandler creates an HTTP handler for metrics.
func NewHTTPHandler(gatherer Gatherer, opts HandlerOpts) http.Handler {
	return HandlerForWithOpts(gatherer, opts)
}
