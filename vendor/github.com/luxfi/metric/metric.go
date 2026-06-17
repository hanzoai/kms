// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"context"
	"time"
)

// CounterOpts configures a counter metric.
type CounterOpts struct {
	Namespace   string
	Subsystem   string
	Name        string
	Help        string
	ConstLabels Labels
}

// GaugeOpts configures a gauge metric.
type GaugeOpts struct {
	Namespace   string
	Subsystem   string
	Name        string
	Help        string
	ConstLabels Labels
}

// HistogramOpts configures a histogram metric.
type HistogramOpts struct {
	Namespace   string
	Subsystem   string
	Name        string
	Help        string
	ConstLabels Labels
	Buckets     []float64
}

// SummaryOpts configures a summary metric.
type SummaryOpts struct {
	Namespace   string
	Subsystem   string
	Name        string
	Help        string
	ConstLabels Labels
	Objectives  map[float64]float64
}

// Counter is a metric that can only increase.
type Counter interface {
	Inc()
	Add(float64)
	Get() float64
}

// Gauge is a metric that can increase or decrease.
type Gauge interface {
	Set(float64)
	Inc()
	Dec()
	Add(float64)
	Sub(float64)
	Get() float64
}

// Histogram samples observations and counts them in configurable buckets.
type Histogram interface {
	Observe(float64)
}

// Summary captures individual observations and provides quantiles.
type Summary interface {
	Observe(float64)
}

// Timer measures durations.
type Timer interface {
	Start() func()
	ObserveTime(time.Duration)
}

// Labels represents a set of label key-value pairs.
type Labels map[string]string

// Metrics is the main interface for creating metrics.
type Metrics interface {
	NewCounter(name, help string) Counter
	NewCounterVec(name, help string, labelNames []string) CounterVec
	NewGauge(name, help string) Gauge
	NewGaugeVec(name, help string, labelNames []string) GaugeVec
	NewHistogram(name, help string, buckets []float64) Histogram
	NewHistogramVec(name, help string, labelNames []string, buckets []float64) HistogramVec
	NewSummary(name, help string, objectives map[float64]float64) Summary
	NewSummaryVec(name, help string, labelNames []string, objectives map[float64]float64) SummaryVec
	Registry() Registry
}

// Factory creates new metrics instances.
type Factory interface {
	New(namespace string) Metrics
	NewWithRegistry(namespace string, registry Registry) Metrics
}

// CounterVec is a labeled counter collection.
type CounterVec interface {
	With(Labels) Counter
	WithLabelValues(...string) Counter
}

// GaugeVec is a labeled gauge collection.
type GaugeVec interface {
	With(Labels) Gauge
	WithLabelValues(...string) Gauge
}

// HistogramVec is a labeled histogram collection.
type HistogramVec interface {
	With(Labels) Histogram
	WithLabelValues(...string) Histogram
}

// SummaryVec is a labeled summary collection.
type SummaryVec interface {
	With(Labels) Summary
	WithLabelValues(...string) Summary
}

// MetricsHTTPHandler handles HTTP requests for metrics.
type MetricsHTTPHandler interface {
	ServeHTTP(w ResponseWriter, r *Request)
}

// ResponseWriter is an interface for writing HTTP responses.
type ResponseWriter interface {
	Write([]byte) (int, error)
	WriteHeader(int)
	Header() map[string][]string
}

// Request represents an HTTP request.
type Request interface {
	Context() context.Context
	Method() string
	URL() string
}

// DefaultRegistry is the default in-process registry used by package-level helpers.
var DefaultRegistry Registry = NewRegistry()

// Global factory instance.
var defaultFactory Factory = NewFactoryWithRegistry(DefaultRegistry)

// SetFactory sets the global metrics factory.
func SetFactory(factory Factory) {
	defaultFactory = factory
}

// New creates a new metrics instance with the given namespace.
func New(namespace string) Metrics {
	return defaultFactory.New(namespace)
}

// NewWithRegistry creates a new metrics instance with the provided registry.
func NewWithRegistry(namespace string, registry Registry) Metrics {
	return defaultFactory.NewWithRegistry(namespace, registry)
}

// NewCounter creates a new counter with the given options.
func NewCounter(opts CounterOpts) Counter {
	prefix := AppendNamespace(opts.Namespace, opts.Subsystem)
	return DefaultRegistry.NewCounter(prefixedName(prefix, opts.Name), opts.Help)
}

// NewGauge creates a new gauge with the given options.
func NewGauge(opts GaugeOpts) Gauge {
	prefix := AppendNamespace(opts.Namespace, opts.Subsystem)
	return DefaultRegistry.NewGauge(prefixedName(prefix, opts.Name), opts.Help)
}

// NewHistogram creates a new histogram with the given options.
func NewHistogram(opts HistogramOpts) Histogram {
	prefix := AppendNamespace(opts.Namespace, opts.Subsystem)
	return DefaultRegistry.NewHistogram(prefixedName(prefix, opts.Name), opts.Help, opts.Buckets)
}

// NewSummary creates a new summary with the given options.
func NewSummary(opts SummaryOpts) Summary {
	prefix := AppendNamespace(opts.Namespace, opts.Subsystem)
	return DefaultRegistry.NewSummary(prefixedName(prefix, opts.Name), opts.Help, opts.Objectives)
}

// NewCounterVec creates a new counter vector with the given options.
func NewCounterVec(opts CounterOpts, labelNames []string) CounterVec {
	prefix := AppendNamespace(opts.Namespace, opts.Subsystem)
	return DefaultRegistry.NewCounterVec(prefixedName(prefix, opts.Name), opts.Help, labelNames)
}

// NewGaugeVec creates a new gauge vector with the given options.
func NewGaugeVec(opts GaugeOpts, labelNames []string) GaugeVec {
	prefix := AppendNamespace(opts.Namespace, opts.Subsystem)
	return DefaultRegistry.NewGaugeVec(prefixedName(prefix, opts.Name), opts.Help, labelNames)
}

// NewHistogramVec creates a new histogram vector with the given options.
func NewHistogramVec(opts HistogramOpts, labelNames []string) HistogramVec {
	prefix := AppendNamespace(opts.Namespace, opts.Subsystem)
	return DefaultRegistry.NewHistogramVec(prefixedName(prefix, opts.Name), opts.Help, labelNames, opts.Buckets)
}

// NewSummaryVec creates a new summary vector with the given options.
func NewSummaryVec(opts SummaryOpts, labelNames []string) SummaryVec {
	prefix := AppendNamespace(opts.Namespace, opts.Subsystem)
	return DefaultRegistry.NewSummaryVec(prefixedName(prefix, opts.Name), opts.Help, labelNames, opts.Objectives)
}
