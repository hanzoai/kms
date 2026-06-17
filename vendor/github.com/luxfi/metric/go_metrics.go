// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"io"
	"runtime"
	"time"
)

// GatherGoMetrics returns metric families describing the Go runtime.
func GatherGoMetrics() ([]*MetricFamily, error) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	families := []*MetricFamily{
		{
			Name:    "go_goroutines",
			Type:    MetricTypeGauge,
			Metrics: []Metric{{Value: MetricValue{Value: float64(runtime.NumGoroutine())}}},
		},
		{
			Name:    "go_memstats_alloc_bytes",
			Type:    MetricTypeGauge,
			Metrics: []Metric{{Value: MetricValue{Value: float64(ms.Alloc)}}},
		},
		{
			Name:    "go_memstats_sys_bytes",
			Type:    MetricTypeGauge,
			Metrics: []Metric{{Value: MetricValue{Value: float64(ms.Sys)}}},
		},
		{
			Name:    "go_memstats_heap_objects",
			Type:    MetricTypeGauge,
			Metrics: []Metric{{Value: MetricValue{Value: float64(ms.HeapObjects)}}},
		},
		{
			Name:    "go_memstats_last_gc_time_seconds",
			Type:    MetricTypeGauge,
			Metrics: []Metric{{Value: MetricValue{Value: float64(ms.LastGC) / float64(time.Second)}}},
		},
	}

	return families, nil
}

// WriteGoMetrics writes Go runtime metrics to w in the text format.
func WriteGoMetrics(w io.Writer) error {
	families, err := GatherGoMetrics()
	if err != nil {
		return err
	}
	return EncodeText(w, families)
}

type goCollector struct{}

func (c *goCollector) Gather() ([]*MetricFamily, error) {
	return GatherGoMetrics()
}
