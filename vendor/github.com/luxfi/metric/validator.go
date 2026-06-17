// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"fmt"
	"regexp"
)

var (
	metricNameRE = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelNameRE  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// ValidateMetricName validates a metric name against the Prometheus text format rules.
func ValidateMetricName(name string) error {
	if name == "" {
		return fmt.Errorf("metric name is empty")
	}
	if !metricNameRE.MatchString(name) {
		return fmt.Errorf("invalid metric name %q", name)
	}
	return nil
}

// ValidateLabelName validates a label name against the Prometheus text format rules.
func ValidateLabelName(name string) error {
	if name == "" {
		return fmt.Errorf("label name is empty")
	}
	if !labelNameRE.MatchString(name) {
		return fmt.Errorf("invalid label name %q", name)
	}
	return nil
}

// ValidateLabels validates all label names in the provided map.
func ValidateLabels(labels Labels) error {
	for k := range labels {
		if err := ValidateLabelName(k); err != nil {
			return err
		}
	}
	return nil
}

// IsValidMetricName returns true if name is a valid metric name.
func IsValidMetricName(name string) bool {
	return ValidateMetricName(name) == nil
}

// IsValidLabelName returns true if name is a valid label name.
func IsValidLabelName(name string) bool {
	return ValidateLabelName(name) == nil
}
