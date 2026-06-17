//go:build !grpc

// Copyright 2013 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package io_metric_client provides metric types for Prometheus-compatible metrics.
// This is the native Go implementation without protobuf dependency.
package io_metric_client

import (
	"encoding/json"
	"time"
)

// MetricType defines the type of a metric.
type MetricType int32

const (
	// MetricType_COUNTER must use the Metric field "counter".
	MetricType_COUNTER MetricType = 0
	// MetricType_GAUGE must use the Metric field "gauge".
	MetricType_GAUGE MetricType = 1
	// MetricType_SUMMARY must use the Metric field "summary".
	MetricType_SUMMARY MetricType = 2
	// MetricType_UNTYPED must use the Metric field "untyped".
	MetricType_UNTYPED MetricType = 3
	// MetricType_HISTOGRAM must use the Metric field "histogram".
	MetricType_HISTOGRAM MetricType = 4
	// MetricType_GAUGE_HISTOGRAM must use the Metric field "histogram".
	MetricType_GAUGE_HISTOGRAM MetricType = 5
)

// MetricType_name maps enum values to names.
var MetricType_name = map[int32]string{
	0: "COUNTER",
	1: "GAUGE",
	2: "SUMMARY",
	3: "UNTYPED",
	4: "HISTOGRAM",
	5: "GAUGE_HISTOGRAM",
}

// MetricType_value maps names to enum values.
var MetricType_value = map[string]int32{
	"COUNTER":         0,
	"GAUGE":           1,
	"SUMMARY":         2,
	"UNTYPED":         3,
	"HISTOGRAM":       4,
	"GAUGE_HISTOGRAM": 5,
}

// Enum returns a pointer to the MetricType.
func (x MetricType) Enum() *MetricType {
	p := new(MetricType)
	*p = x
	return p
}

// String returns the string representation of the MetricType.
func (x MetricType) String() string {
	if name, ok := MetricType_name[int32(x)]; ok {
		return name
	}
	return "UNKNOWN"
}

// Timestamp represents a point in time.
type Timestamp struct {
	Seconds int64 `json:"seconds,omitempty"`
	Nanos   int32 `json:"nanos,omitempty"`
}

// NewTimestamp creates a Timestamp from a time.Time.
func NewTimestamp(t time.Time) *Timestamp {
	return &Timestamp{
		Seconds: t.Unix(),
		Nanos:   int32(t.Nanosecond()),
	}
}

// AsTime converts the Timestamp to a time.Time.
func (t *Timestamp) AsTime() time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Unix(t.Seconds, int64(t.Nanos))
}

// LabelPair is a name-value pair for metric labels.
type LabelPair struct {
	Name  *string `json:"name,omitempty"`
	Value *string `json:"value,omitempty"`
}

// Reset resets the LabelPair to its zero value.
func (x *LabelPair) Reset() {
	*x = LabelPair{}
}

// String returns the JSON representation of the LabelPair.
func (x *LabelPair) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetName returns the Name field value or empty string if nil.
func (x *LabelPair) GetName() string {
	if x != nil && x.Name != nil {
		return *x.Name
	}
	return ""
}

// GetValue returns the Value field value or empty string if nil.
func (x *LabelPair) GetValue() string {
	if x != nil && x.Value != nil {
		return *x.Value
	}
	return ""
}

// Gauge represents a gauge metric value.
type Gauge struct {
	Value *float64 `json:"value,omitempty"`
}

// Reset resets the Gauge to its zero value.
func (x *Gauge) Reset() {
	*x = Gauge{}
}

// String returns the JSON representation of the Gauge.
func (x *Gauge) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetValue returns the Value field value or 0 if nil.
func (x *Gauge) GetValue() float64 {
	if x != nil && x.Value != nil {
		return *x.Value
	}
	return 0
}

// Counter represents a counter metric value.
type Counter struct {
	Value            *float64   `json:"value,omitempty"`
	Exemplar         *Exemplar  `json:"exemplar,omitempty"`
	CreatedTimestamp *Timestamp `json:"created_timestamp,omitempty"`
}

// Reset resets the Counter to its zero value.
func (x *Counter) Reset() {
	*x = Counter{}
}

// String returns the JSON representation of the Counter.
func (x *Counter) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetValue returns the Value field value or 0 if nil.
func (x *Counter) GetValue() float64 {
	if x != nil && x.Value != nil {
		return *x.Value
	}
	return 0
}

// GetExemplar returns the Exemplar field value or nil if not set.
func (x *Counter) GetExemplar() *Exemplar {
	if x != nil {
		return x.Exemplar
	}
	return nil
}

// GetCreatedTimestamp returns the CreatedTimestamp field value or nil if not set.
func (x *Counter) GetCreatedTimestamp() *Timestamp {
	if x != nil {
		return x.CreatedTimestamp
	}
	return nil
}

// Quantile represents a quantile value in a summary.
type Quantile struct {
	Quantile *float64 `json:"quantile,omitempty"`
	Value    *float64 `json:"value,omitempty"`
}

// Reset resets the Quantile to its zero value.
func (x *Quantile) Reset() {
	*x = Quantile{}
}

// String returns the JSON representation of the Quantile.
func (x *Quantile) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetQuantile returns the Quantile field value or 0 if nil.
func (x *Quantile) GetQuantile() float64 {
	if x != nil && x.Quantile != nil {
		return *x.Quantile
	}
	return 0
}

// GetValue returns the Value field value or 0 if nil.
func (x *Quantile) GetValue() float64 {
	if x != nil && x.Value != nil {
		return *x.Value
	}
	return 0
}

// Summary represents a summary metric value.
type Summary struct {
	SampleCount      *uint64     `json:"sample_count,omitempty"`
	SampleSum        *float64    `json:"sample_sum,omitempty"`
	Quantile         []*Quantile `json:"quantile,omitempty"`
	CreatedTimestamp *Timestamp  `json:"created_timestamp,omitempty"`
}

// Reset resets the Summary to its zero value.
func (x *Summary) Reset() {
	*x = Summary{}
}

// String returns the JSON representation of the Summary.
func (x *Summary) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetSampleCount returns the SampleCount field value or 0 if nil.
func (x *Summary) GetSampleCount() uint64 {
	if x != nil && x.SampleCount != nil {
		return *x.SampleCount
	}
	return 0
}

// GetSampleSum returns the SampleSum field value or 0 if nil.
func (x *Summary) GetSampleSum() float64 {
	if x != nil && x.SampleSum != nil {
		return *x.SampleSum
	}
	return 0
}

// GetQuantile returns the Quantile field slice or nil if not set.
func (x *Summary) GetQuantile() []*Quantile {
	if x != nil {
		return x.Quantile
	}
	return nil
}

// GetCreatedTimestamp returns the CreatedTimestamp field value or nil if not set.
func (x *Summary) GetCreatedTimestamp() *Timestamp {
	if x != nil {
		return x.CreatedTimestamp
	}
	return nil
}

// Untyped represents an untyped metric value.
type Untyped struct {
	Value *float64 `json:"value,omitempty"`
}

// Reset resets the Untyped to its zero value.
func (x *Untyped) Reset() {
	*x = Untyped{}
}

// String returns the JSON representation of the Untyped.
func (x *Untyped) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetValue returns the Value field value or 0 if nil.
func (x *Untyped) GetValue() float64 {
	if x != nil && x.Value != nil {
		return *x.Value
	}
	return 0
}

// Histogram represents a histogram metric value.
type Histogram struct {
	SampleCount      *uint64       `json:"sample_count,omitempty"`
	SampleCountFloat *float64      `json:"sample_count_float,omitempty"`
	SampleSum        *float64      `json:"sample_sum,omitempty"`
	Bucket           []*Bucket     `json:"bucket,omitempty"`
	CreatedTimestamp *Timestamp    `json:"created_timestamp,omitempty"`
	Schema           *int32        `json:"schema,omitempty"`
	ZeroThreshold    *float64      `json:"zero_threshold,omitempty"`
	ZeroCount        *uint64       `json:"zero_count,omitempty"`
	ZeroCountFloat   *float64      `json:"zero_count_float,omitempty"`
	NegativeSpan     []*BucketSpan `json:"negative_span,omitempty"`
	NegativeDelta    []int64       `json:"negative_delta,omitempty"`
	NegativeCount    []float64     `json:"negative_count,omitempty"`
	PositiveSpan     []*BucketSpan `json:"positive_span,omitempty"`
	PositiveDelta    []int64       `json:"positive_delta,omitempty"`
	PositiveCount    []float64     `json:"positive_count,omitempty"`
	Exemplars        []*Exemplar   `json:"exemplars,omitempty"`
}

// Reset resets the Histogram to its zero value.
func (x *Histogram) Reset() {
	*x = Histogram{}
}

// String returns the JSON representation of the Histogram.
func (x *Histogram) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetSampleCount returns the SampleCount field value or 0 if nil.
func (x *Histogram) GetSampleCount() uint64 {
	if x != nil && x.SampleCount != nil {
		return *x.SampleCount
	}
	return 0
}

// GetSampleCountFloat returns the SampleCountFloat field value or 0 if nil.
func (x *Histogram) GetSampleCountFloat() float64 {
	if x != nil && x.SampleCountFloat != nil {
		return *x.SampleCountFloat
	}
	return 0
}

// GetSampleSum returns the SampleSum field value or 0 if nil.
func (x *Histogram) GetSampleSum() float64 {
	if x != nil && x.SampleSum != nil {
		return *x.SampleSum
	}
	return 0
}

// GetBucket returns the Bucket field slice or nil if not set.
func (x *Histogram) GetBucket() []*Bucket {
	if x != nil {
		return x.Bucket
	}
	return nil
}

// GetCreatedTimestamp returns the CreatedTimestamp field value or nil if not set.
func (x *Histogram) GetCreatedTimestamp() *Timestamp {
	if x != nil {
		return x.CreatedTimestamp
	}
	return nil
}

// GetSchema returns the Schema field value or 0 if nil.
func (x *Histogram) GetSchema() int32 {
	if x != nil && x.Schema != nil {
		return *x.Schema
	}
	return 0
}

// GetZeroThreshold returns the ZeroThreshold field value or 0 if nil.
func (x *Histogram) GetZeroThreshold() float64 {
	if x != nil && x.ZeroThreshold != nil {
		return *x.ZeroThreshold
	}
	return 0
}

// GetZeroCount returns the ZeroCount field value or 0 if nil.
func (x *Histogram) GetZeroCount() uint64 {
	if x != nil && x.ZeroCount != nil {
		return *x.ZeroCount
	}
	return 0
}

// GetZeroCountFloat returns the ZeroCountFloat field value or 0 if nil.
func (x *Histogram) GetZeroCountFloat() float64 {
	if x != nil && x.ZeroCountFloat != nil {
		return *x.ZeroCountFloat
	}
	return 0
}

// GetNegativeSpan returns the NegativeSpan field slice or nil if not set.
func (x *Histogram) GetNegativeSpan() []*BucketSpan {
	if x != nil {
		return x.NegativeSpan
	}
	return nil
}

// GetNegativeDelta returns the NegativeDelta field slice or nil if not set.
func (x *Histogram) GetNegativeDelta() []int64 {
	if x != nil {
		return x.NegativeDelta
	}
	return nil
}

// GetNegativeCount returns the NegativeCount field slice or nil if not set.
func (x *Histogram) GetNegativeCount() []float64 {
	if x != nil {
		return x.NegativeCount
	}
	return nil
}

// GetPositiveSpan returns the PositiveSpan field slice or nil if not set.
func (x *Histogram) GetPositiveSpan() []*BucketSpan {
	if x != nil {
		return x.PositiveSpan
	}
	return nil
}

// GetPositiveDelta returns the PositiveDelta field slice or nil if not set.
func (x *Histogram) GetPositiveDelta() []int64 {
	if x != nil {
		return x.PositiveDelta
	}
	return nil
}

// GetPositiveCount returns the PositiveCount field slice or nil if not set.
func (x *Histogram) GetPositiveCount() []float64 {
	if x != nil {
		return x.PositiveCount
	}
	return nil
}

// GetExemplars returns the Exemplars field slice or nil if not set.
func (x *Histogram) GetExemplars() []*Exemplar {
	if x != nil {
		return x.Exemplars
	}
	return nil
}

// Bucket represents a histogram bucket.
type Bucket struct {
	CumulativeCount      *uint64   `json:"cumulative_count,omitempty"`
	CumulativeCountFloat *float64  `json:"cumulative_count_float,omitempty"`
	UpperBound           *float64  `json:"upper_bound,omitempty"`
	Exemplar             *Exemplar `json:"exemplar,omitempty"`
}

// Reset resets the Bucket to its zero value.
func (x *Bucket) Reset() {
	*x = Bucket{}
}

// String returns the JSON representation of the Bucket.
func (x *Bucket) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetCumulativeCount returns the CumulativeCount field value or 0 if nil.
func (x *Bucket) GetCumulativeCount() uint64 {
	if x != nil && x.CumulativeCount != nil {
		return *x.CumulativeCount
	}
	return 0
}

// GetCumulativeCountFloat returns the CumulativeCountFloat field value or 0 if nil.
func (x *Bucket) GetCumulativeCountFloat() float64 {
	if x != nil && x.CumulativeCountFloat != nil {
		return *x.CumulativeCountFloat
	}
	return 0
}

// GetUpperBound returns the UpperBound field value or 0 if nil.
func (x *Bucket) GetUpperBound() float64 {
	if x != nil && x.UpperBound != nil {
		return *x.UpperBound
	}
	return 0
}

// GetExemplar returns the Exemplar field value or nil if not set.
func (x *Bucket) GetExemplar() *Exemplar {
	if x != nil {
		return x.Exemplar
	}
	return nil
}

// BucketSpan defines a number of consecutive buckets in a native histogram.
type BucketSpan struct {
	Offset *int32  `json:"offset,omitempty"`
	Length *uint32 `json:"length,omitempty"`
}

// Reset resets the BucketSpan to its zero value.
func (x *BucketSpan) Reset() {
	*x = BucketSpan{}
}

// String returns the JSON representation of the BucketSpan.
func (x *BucketSpan) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetOffset returns the Offset field value or 0 if nil.
func (x *BucketSpan) GetOffset() int32 {
	if x != nil && x.Offset != nil {
		return *x.Offset
	}
	return 0
}

// GetLength returns the Length field value or 0 if nil.
func (x *BucketSpan) GetLength() uint32 {
	if x != nil && x.Length != nil {
		return *x.Length
	}
	return 0
}

// Exemplar represents an exemplar for a metric.
type Exemplar struct {
	Label     []*LabelPair `json:"label,omitempty"`
	Value     *float64     `json:"value,omitempty"`
	Timestamp *Timestamp   `json:"timestamp,omitempty"`
}

// Reset resets the Exemplar to its zero value.
func (x *Exemplar) Reset() {
	*x = Exemplar{}
}

// String returns the JSON representation of the Exemplar.
func (x *Exemplar) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetLabel returns the Label field slice or nil if not set.
func (x *Exemplar) GetLabel() []*LabelPair {
	if x != nil {
		return x.Label
	}
	return nil
}

// GetValue returns the Value field value or 0 if nil.
func (x *Exemplar) GetValue() float64 {
	if x != nil && x.Value != nil {
		return *x.Value
	}
	return 0
}

// GetTimestamp returns the Timestamp field value or nil if not set.
func (x *Exemplar) GetTimestamp() *Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

// Metric represents a single metric with its labels and values.
type Metric struct {
	Label       []*LabelPair `json:"label,omitempty"`
	Gauge       *Gauge       `json:"gauge,omitempty"`
	Counter     *Counter     `json:"counter,omitempty"`
	Summary     *Summary     `json:"summary,omitempty"`
	Untyped     *Untyped     `json:"untyped,omitempty"`
	Histogram   *Histogram   `json:"histogram,omitempty"`
	TimestampMs *int64       `json:"timestamp_ms,omitempty"`
}

// Reset resets the Metric to its zero value.
func (x *Metric) Reset() {
	*x = Metric{}
}

// String returns the JSON representation of the Metric.
func (x *Metric) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetLabel returns the Label field slice or nil if not set.
func (x *Metric) GetLabel() []*LabelPair {
	if x != nil {
		return x.Label
	}
	return nil
}

// GetGauge returns the Gauge field value or nil if not set.
func (x *Metric) GetGauge() *Gauge {
	if x != nil {
		return x.Gauge
	}
	return nil
}

// GetCounter returns the Counter field value or nil if not set.
func (x *Metric) GetCounter() *Counter {
	if x != nil {
		return x.Counter
	}
	return nil
}

// GetSummary returns the Summary field value or nil if not set.
func (x *Metric) GetSummary() *Summary {
	if x != nil {
		return x.Summary
	}
	return nil
}

// GetUntyped returns the Untyped field value or nil if not set.
func (x *Metric) GetUntyped() *Untyped {
	if x != nil {
		return x.Untyped
	}
	return nil
}

// GetHistogram returns the Histogram field value or nil if not set.
func (x *Metric) GetHistogram() *Histogram {
	if x != nil {
		return x.Histogram
	}
	return nil
}

// GetTimestampMs returns the TimestampMs field value or 0 if nil.
func (x *Metric) GetTimestampMs() int64 {
	if x != nil && x.TimestampMs != nil {
		return *x.TimestampMs
	}
	return 0
}

// MetricFamily is a collection of metrics with the same name and type.
type MetricFamily struct {
	Name   *string     `json:"name,omitempty"`
	Help   *string     `json:"help,omitempty"`
	Type   *MetricType `json:"type,omitempty"`
	Metric []*Metric   `json:"metric,omitempty"`
	Unit   *string     `json:"unit,omitempty"`
}

// Reset resets the MetricFamily to its zero value.
func (x *MetricFamily) Reset() {
	*x = MetricFamily{}
}

// String returns the JSON representation of the MetricFamily.
func (x *MetricFamily) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}

// GetName returns the Name field value or empty string if nil.
func (x *MetricFamily) GetName() string {
	if x != nil && x.Name != nil {
		return *x.Name
	}
	return ""
}

// GetHelp returns the Help field value or empty string if nil.
func (x *MetricFamily) GetHelp() string {
	if x != nil && x.Help != nil {
		return *x.Help
	}
	return ""
}

// GetType returns the Type field value or MetricType_COUNTER if nil.
func (x *MetricFamily) GetType() MetricType {
	if x != nil && x.Type != nil {
		return *x.Type
	}
	return MetricType_COUNTER
}

// GetMetric returns the Metric field slice or nil if not set.
func (x *MetricFamily) GetMetric() []*Metric {
	if x != nil {
		return x.Metric
	}
	return nil
}

// GetUnit returns the Unit field value or empty string if nil.
func (x *MetricFamily) GetUnit() string {
	if x != nil && x.Unit != nil {
		return *x.Unit
	}
	return ""
}
