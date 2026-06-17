// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

// noopCounter is a counter that does nothing.
type noopCounter struct{ value float64 }

func (n *noopCounter) Inc()          { n.value++ }
func (n *noopCounter) Add(v float64) { n.value += v }
func (n *noopCounter) Get() float64  { return n.value }

// noopGauge is a gauge that does nothing.
type noopGauge struct{ value float64 }

func (n *noopGauge) Set(v float64) { n.value = v }
func (n *noopGauge) Inc()          { n.value++ }
func (n *noopGauge) Dec()          { n.value-- }
func (n *noopGauge) Add(v float64) { n.value += v }
func (n *noopGauge) Sub(v float64) { n.value -= v }
func (n *noopGauge) Get() float64  { return n.value }

// noopHistogram is a histogram that does nothing.
type noopHistogram struct{}

func (n *noopHistogram) Observe(float64) {}

// noopSummary is a summary that does nothing.
type noopSummary struct{}

func (n *noopSummary) Observe(float64) {}

// noopCounterVec is a counter vector that does nothing.
type noopCounterVec struct{}

func (n *noopCounterVec) With(Labels) Counter               { return &noopCounter{} }
func (n *noopCounterVec) WithLabelValues(...string) Counter { return &noopCounter{} }

// noopGaugeVec is a gauge vector that does nothing.
type noopGaugeVec struct{}

func (n *noopGaugeVec) With(Labels) Gauge               { return &noopGauge{} }
func (n *noopGaugeVec) WithLabelValues(...string) Gauge { return &noopGauge{} }

// noopHistogramVec is a histogram vector that does nothing.
type noopHistogramVec struct{}

func (n *noopHistogramVec) With(Labels) Histogram               { return &noopHistogram{} }
func (n *noopHistogramVec) WithLabelValues(...string) Histogram { return &noopHistogram{} }

// noopSummaryVec is a summary vector that does nothing.
type noopSummaryVec struct{}

func (n *noopSummaryVec) With(Labels) Summary               { return &noopSummary{} }
func (n *noopSummaryVec) WithLabelValues(...string) Summary { return &noopSummary{} }

// noopRegistry provides a registry that gathers nothing.
type noopRegistry struct{}

func newNoopRegistry() Registry { return &noopRegistry{} }

func (r *noopRegistry) Register(_ Collector) error  { return nil }
func (r *noopRegistry) MustRegister(_ ...Collector) {}
func (r *noopRegistry) Gather() ([]*MetricFamily, error) {
	return nil, nil
}

func (r *noopRegistry) NewCounter(name, help string) Counter {
	return &noopCounter{}
}

func (r *noopRegistry) NewCounterVec(name, help string, labelNames []string) CounterVec {
	return &noopCounterVec{}
}

func (r *noopRegistry) NewGauge(name, help string) Gauge {
	return &noopGauge{}
}

func (r *noopRegistry) NewGaugeVec(name, help string, labelNames []string) GaugeVec {
	return &noopGaugeVec{}
}

func (r *noopRegistry) NewHistogram(name, help string, buckets []float64) Histogram {
	return &noopHistogram{}
}

func (r *noopRegistry) NewHistogramVec(name, help string, labelNames []string, buckets []float64) HistogramVec {
	return &noopHistogramVec{}
}

func (r *noopRegistry) NewSummary(name, help string, objectives map[float64]float64) Summary {
	return &noopSummary{}
}

func (r *noopRegistry) NewSummaryVec(name, help string, labelNames []string, objectives map[float64]float64) SummaryVec {
	return &noopSummaryVec{}
}

func (r *noopRegistry) Registry() Registry {
	return r
}

// noopMetrics is a metrics implementation that does nothing.
type noopMetrics struct {
	registry Registry
}

func (n *noopMetrics) NewCounter(name, help string) Counter {
	return &noopCounter{}
}

func (n *noopMetrics) NewCounterVec(name, help string, labelNames []string) CounterVec {
	return &noopCounterVec{}
}

func (n *noopMetrics) NewGauge(name, help string) Gauge {
	return &noopGauge{}
}

func (n *noopMetrics) NewGaugeVec(name, help string, labelNames []string) GaugeVec {
	return &noopGaugeVec{}
}

func (n *noopMetrics) NewHistogram(name, help string, buckets []float64) Histogram {
	return &noopHistogram{}
}

func (n *noopMetrics) NewHistogramVec(name, help string, labelNames []string, buckets []float64) HistogramVec {
	return &noopHistogramVec{}
}

func (n *noopMetrics) NewSummary(name, help string, objectives map[float64]float64) Summary {
	return &noopSummary{}
}

func (n *noopMetrics) NewSummaryVec(name, help string, labelNames []string, objectives map[float64]float64) SummaryVec {
	return &noopSummaryVec{}
}

func (n *noopMetrics) Registry() Registry {
	return n.registry
}

// NewNoOpMetrics returns a no-op metrics instance.
func NewNoOpMetrics(namespace string) Metrics {
	return &noopMetrics{registry: newNoopRegistry()}
}

// NewNoOpRegistry returns a no-op registry.
func NewNoOpRegistry() Registry {
	return newNoopRegistry()
}

// NewNoOp returns a no-op metrics instance without requiring a namespace.
func NewNoOp() Metrics {
	return NewNoOpMetrics("")
}

// noopFactory produces no-op metrics.
type noopFactory struct{}

func (f *noopFactory) New(namespace string) Metrics {
	return NewNoOpMetrics(namespace)
}

func (f *noopFactory) NewWithRegistry(namespace string, _ Registry) Metrics {
	return NewNoOpMetrics(namespace)
}

// NewNoOpFactory returns a factory that produces no-op metrics.
func NewNoOpFactory() Factory {
	return &noopFactory{}
}

// NewNoopGauge returns a no-op gauge.
func NewNoopGauge() Gauge {
	return &noopGauge{}
}

// NewNoopCounter returns a no-op counter.
func NewNoopCounter() Counter {
	return &noopCounter{}
}

// NewNoopHistogram returns a no-op histogram.
func NewNoopHistogram() Histogram {
	return &noopHistogram{}
}

// NewNoopSummary returns a no-op summary.
func NewNoopSummary() Summary {
	return &noopSummary{}
}
