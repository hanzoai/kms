// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HandlerErrorHandling defines behavior on gather errors.
type HandlerErrorHandling int

const (
	// HandlerErrorHandlingHTTPError causes the handler to return HTTP 500 on error.
	HandlerErrorHandlingHTTPError HandlerErrorHandling = iota
	// HandlerErrorHandlingContinue writes what it can and logs the error.
	HandlerErrorHandlingContinue
)

// HandlerOpts configures metrics handlers.
type HandlerOpts struct {
	// Timeout overrides the scrape timeout. If zero, the scrape header is used if present.
	Timeout time.Duration
	// ErrorHandling controls how gather errors are handled.
	ErrorHandling HandlerErrorHandling
	// ErrorLog is used when ErrorHandling is Continue.
	ErrorLog interface{ Println(...any) }
}

// HTTPHandlerOpts is an alias for HandlerOpts for compatibility.
type HTTPHandlerOpts = HandlerOpts

// HandlerFor returns an HTTP handler for the provided gatherer.
func HandlerFor(gatherer Gatherer) http.Handler {
	return HandlerForWithOpts(gatherer, HandlerOpts{})
}

// HandlerForWithOpts returns an HTTP handler for the provided gatherer and options.
func HandlerForWithOpts(gatherer Gatherer, opts HandlerOpts) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		timeout := opts.Timeout
		if timeout == 0 {
			timeout = parseScrapeTimeout(r)
		}
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}

		families, err := gatherWithContext(ctx, gatherer)
		if err != nil {
			switch opts.ErrorHandling {
			case HandlerErrorHandlingContinue:
				if opts.ErrorLog != nil {
					opts.ErrorLog.Println("metrics gather error:", err)
				}
			default:
				http.Error(w, "metrics gather error", http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := EncodeText(w, families); err != nil {
			if opts.ErrorHandling == HandlerErrorHandlingContinue && opts.ErrorLog != nil {
				opts.ErrorLog.Println("metrics encode error:", err)
				return
			}
			http.Error(w, "metrics encode error", http.StatusInternalServerError)
			return
		}
	})
}

func gatherWithContext(ctx context.Context, gatherer Gatherer) ([]*MetricFamily, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return gatherer.Gather()
}

// parseScrapeTimeout parses the scrape timeout header.
func parseScrapeTimeout(r *http.Request) time.Duration {
	headerVal := r.Header.Get("X-Scrape-Timeout-Seconds")
	if headerVal == "" {
		headerVal = r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds")
	}
	if headerVal == "" {
		return 0
	}
	seconds, err := strconv.ParseFloat(headerVal, 64)
	if err != nil {
		return 0
	}
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds * float64(time.Second))
}

// Handler is a convenience method for exposing the default registry.
func Handler() http.Handler {
	return HandlerFor(NewRegistry())
}

// ValidateGatherer returns a non-nil error if the gatherer is nil.
func ValidateGatherer(gatherer Gatherer) error {
	if gatherer == nil {
		return fmt.Errorf("nil gatherer")
	}
	return nil
}

// EncodeText encodes metric families in the metrics text format.
func EncodeText(w io.Writer, families []*MetricFamily) error {
	for _, mf := range families {
		if mf == nil {
			continue
		}

		// Write HELP line
		if mf.Help != "" {
			fmt.Fprintf(w, "# HELP %s %s\n", mf.Name, escapeHelp(mf.Help))
		}

		// Write TYPE line
		fmt.Fprintf(w, "# TYPE %s %s\n", mf.Name, mf.Type.String())

		// Write metrics
		for _, m := range mf.Metrics {
			switch mf.Type {
			case MetricTypeCounter, MetricTypeGauge, MetricTypeUntyped:
				writeMetricLine(w, mf.Name, m.Labels, m.Value.Value)
			case MetricTypeHistogram:
				writeHistogram(w, mf.Name, m)
			case MetricTypeSummary:
				writeSummary(w, mf.Name, m)
			}
		}
	}
	return nil
}

func writeMetricLine(w io.Writer, name string, labels []LabelPair, value float64) {
	if len(labels) == 0 {
		fmt.Fprintf(w, "%s %v\n", name, value)
	} else {
		fmt.Fprintf(w, "%s{%s} %v\n", name, formatLabels(labels), value)
	}
}

func writeHistogram(w io.Writer, name string, m Metric) {
	// Sort buckets by upper bound
	buckets := make([]Bucket, len(m.Value.Buckets))
	copy(buckets, m.Value.Buckets)
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].UpperBound < buckets[j].UpperBound
	})

	for _, b := range buckets {
		labels := append(m.Labels, LabelPair{Name: "le", Value: formatFloat(b.UpperBound)})
		fmt.Fprintf(w, "%s_bucket{%s} %d\n", name, formatLabels(labels), b.CumulativeCount)
	}
	writeMetricLine(w, name+"_sum", m.Labels, m.Value.SampleSum)
	fmt.Fprintf(w, "%s_count%s %d\n", name, formatLabelsWithBraces(m.Labels), m.Value.SampleCount)
}

func writeSummary(w io.Writer, name string, m Metric) {
	for _, q := range m.Value.Quantiles {
		labels := append(m.Labels, LabelPair{Name: "quantile", Value: formatFloat(q.Quantile)})
		fmt.Fprintf(w, "%s{%s} %v\n", name, formatLabels(labels), q.Value)
	}
	writeMetricLine(w, name+"_sum", m.Labels, m.Value.SampleSum)
	fmt.Fprintf(w, "%s_count%s %d\n", name, formatLabelsWithBraces(m.Labels), m.Value.SampleCount)
}

func formatLabels(labels []LabelPair) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = fmt.Sprintf("%s=%q", l.Name, l.Value)
	}
	return strings.Join(parts, ",")
}

func formatLabelsWithBraces(labels []LabelPair) string {
	if len(labels) == 0 {
		return ""
	}
	return "{" + formatLabels(labels) + "}"
}

func formatFloat(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func escapeHelp(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// HTTPHandler creates an HTTP handler for metrics (compatibility alias).
func HTTPHandler(gatherer Gatherer, opts HandlerOpts) http.Handler {
	return HandlerForWithOpts(gatherer, opts)
}
