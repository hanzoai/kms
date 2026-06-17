// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

// TimingMetric measures durations and records them in a histogram.
type TimingMetric = timingMetric

// NewTimingMetric creates a timing metric bound to the provided histogram.
func NewTimingMetric(histogram Histogram) *TimingMetric {
	return newTimingMetric(histogram)
}
