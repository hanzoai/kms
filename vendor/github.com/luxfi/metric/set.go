// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import "io"

// Set groups metrics under a shared registry.
//
// This is a thin wrapper around Registry to provide a single place
// to create and export a collection of metrics.
type Set struct {
	reg Registry
}

// NewSet creates a new metrics set backed by its own registry.
func NewSet() *Set {
	return &Set{reg: NewRegistry()}
}

// Registry returns the underlying registry.
func (s *Set) Registry() Registry {
	return s.reg
}

// NewCounter registers and returns a counter in the set.
func (s *Set) NewCounter(name, help string) Counter {
	return s.reg.NewCounter(name, help)
}

// NewCounterVec registers and returns a counter vector in the set.
func (s *Set) NewCounterVec(name, help string, labelNames []string) CounterVec {
	return s.reg.NewCounterVec(name, help, labelNames)
}

// NewGauge registers and returns a gauge in the set.
func (s *Set) NewGauge(name, help string) Gauge {
	return s.reg.NewGauge(name, help)
}

// NewGaugeVec registers and returns a gauge vector in the set.
func (s *Set) NewGaugeVec(name, help string, labelNames []string) GaugeVec {
	return s.reg.NewGaugeVec(name, help, labelNames)
}

// NewHistogram registers and returns a histogram in the set.
func (s *Set) NewHistogram(name, help string, buckets []float64) Histogram {
	return s.reg.NewHistogram(name, help, buckets)
}

// NewHistogramVec registers and returns a histogram vector in the set.
func (s *Set) NewHistogramVec(name, help string, labelNames []string, buckets []float64) HistogramVec {
	return s.reg.NewHistogramVec(name, help, labelNames, buckets)
}

// NewSummary registers and returns a summary in the set.
func (s *Set) NewSummary(name, help string, objectives map[float64]float64) Summary {
	return s.reg.NewSummary(name, help, objectives)
}

// NewSummaryVec registers and returns a summary vector in the set.
func (s *Set) NewSummaryVec(name, help string, labelNames []string, objectives map[float64]float64) SummaryVec {
	return s.reg.NewSummaryVec(name, help, labelNames, objectives)
}

// Write writes the set metrics to w in the text exposition format.
func (s *Set) Write(w io.Writer) error {
	families, err := s.reg.Gather()
	if err != nil {
		return err
	}
	return EncodeText(w, families)
}
