// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"io"
	"time"
)

var processStartTime = time.Now()

// GatherProcessMetrics returns metric families describing the current process.
func GatherProcessMetrics(opts ProcessCollectorOpts) ([]*MetricFamily, error) {
	start := float64(processStartTime.UnixNano()) / float64(time.Second)

	families := []*MetricFamily{
		{
			Name:    "process_start_time_seconds",
			Type:    MetricTypeGauge,
			Metrics: []Metric{{Value: MetricValue{Value: start}}},
		},
	}

	if cpu, ok := processCPUSeconds(); ok {
		families = append(families, &MetricFamily{
			Name:    "process_cpu_seconds_total",
			Type:    MetricTypeCounter,
			Metrics: []Metric{{Value: MetricValue{Value: cpu}}},
		})
	}

	if rss, ok := processResidentBytes(); ok {
		families = append(families, &MetricFamily{
			Name:    "process_resident_memory_bytes",
			Type:    MetricTypeGauge,
			Metrics: []Metric{{Value: MetricValue{Value: rss}}},
		})
	}

	return families, nil
}

// WriteProcessMetrics writes process metrics to w in the text format.
func WriteProcessMetrics(w io.Writer) error {
	families, err := GatherProcessMetrics(ProcessCollectorOpts{})
	if err != nil {
		return err
	}
	return EncodeText(w, families)
}

type processCollector struct {
	opts ProcessCollectorOpts
}

func (c *processCollector) Gather() ([]*MetricFamily, error) {
	return GatherProcessMetrics(c.opts)
}
