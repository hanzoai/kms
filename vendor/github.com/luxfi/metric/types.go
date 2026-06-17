// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

// MetricType defines the type of a metric.
type MetricType int32

const (
	MetricTypeCounter MetricType = iota
	MetricTypeGauge
	MetricTypeHistogram
	MetricTypeSummary
	MetricTypeUntyped
)

func (t MetricType) String() string {
	switch t {
	case MetricTypeCounter:
		return "counter"
	case MetricTypeGauge:
		return "gauge"
	case MetricTypeHistogram:
		return "histogram"
	case MetricTypeSummary:
		return "summary"
	default:
		return "untyped"
	}
}

// LabelPair is a name-value pair for metric labels.
type LabelPair struct {
	Name  string
	Value string
}

// MetricValue holds the value of a metric.
type MetricValue struct {
	// For counter/gauge
	Value float64

	// For histogram
	SampleCount uint64
	SampleSum   float64
	Buckets     []Bucket

	// For summary
	Quantiles []Quantile
}

// Bucket represents a histogram bucket.
type Bucket struct {
	UpperBound      float64
	CumulativeCount uint64
}

// Quantile represents a summary quantile.
type Quantile struct {
	Quantile float64
	Value    float64
}

// Metric represents a single metric with its labels and value.
type Metric struct {
	Labels []LabelPair
	Value  MetricValue
}

// MetricFamily is a collection of metrics with the same name and type.
type MetricFamily struct {
	Name    string
	Help    string
	Type    MetricType
	Metrics []Metric
}

// ptr returns a pointer to the string (helper for compatibility).
func ptr(s string) *string {
	return &s
}
