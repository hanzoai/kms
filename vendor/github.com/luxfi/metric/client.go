// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Client for requesting metrics from a remote Lux Node instance
type Client struct {
	uri string
}

// NewClient returns a new Metrics API Client
func NewClient(uri string) *Client {
	return &Client{
		uri: uri + "/ext/metrics",
	}
}

// GetMetrics returns the metrics from the connected node. The metrics are
// returned as a map of metric family name to the metric family.
func (c *Client) GetMetrics(ctx context.Context) (map[string]*MetricFamily, error) {
	uri, err := url.Parse(c.uri)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		uri.String(),
		bytes.NewReader(nil),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to issue request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code: %d", resp.StatusCode)
	}

	return ParseText(resp.Body)
}

// TextParser parses the metrics text format.
type TextParser struct{}

// TextToMetricFamilies parses text format into metric families.
func (p *TextParser) TextToMetricFamilies(r io.Reader) (map[string]*MetricFamily, error) {
	return ParseText(r)
}

// ParseText parses the metrics text format into metric families.
func ParseText(r io.Reader) (map[string]*MetricFamily, error) {
	families := make(map[string]*MetricFamily)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "# HELP ") {
			parts := strings.SplitN(line[7:], " ", 2)
			name := parts[0]
			help := ""
			if len(parts) > 1 {
				help = unescapeHelp(parts[1])
			}
			if _, ok := families[name]; !ok {
				families[name] = &MetricFamily{Name: name}
			}
			families[name].Help = help
			continue
		}

		if strings.HasPrefix(line, "# TYPE ") {
			parts := strings.SplitN(line[7:], " ", 2)
			name := parts[0]
			typeStr := ""
			if len(parts) > 1 {
				typeStr = parts[1]
			}
			if _, ok := families[name]; !ok {
				families[name] = &MetricFamily{Name: name}
			}
			families[name].Type = parseMetricType(typeStr)
			continue
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		// Parse metric line
		name, labels, value, err := parseMetricLine(line)
		if err != nil {
			continue // Skip malformed lines
		}

		// Handle histogram/summary suffixes
		baseName := name
		if strings.HasSuffix(name, "_bucket") {
			baseName = strings.TrimSuffix(name, "_bucket")
		} else if strings.HasSuffix(name, "_sum") {
			baseName = strings.TrimSuffix(name, "_sum")
		} else if strings.HasSuffix(name, "_count") {
			baseName = strings.TrimSuffix(name, "_count")
		} else if strings.HasSuffix(name, "_total") {
			baseName = strings.TrimSuffix(name, "_total")
		}

		if _, ok := families[baseName]; !ok {
			families[baseName] = &MetricFamily{Name: baseName, Type: MetricTypeUntyped}
		}
		mf := families[baseName]

		// Add metric to family
		mf.Metrics = append(mf.Metrics, Metric{
			Labels: labels,
			Value:  MetricValue{Value: value},
		})
	}

	return families, scanner.Err()
}

func parseMetricLine(line string) (string, []LabelPair, float64, error) {
	// Find the space before the value
	idx := strings.LastIndex(line, " ")
	if idx == -1 {
		return "", nil, 0, fmt.Errorf("no value found")
	}

	valueStr := strings.TrimSpace(line[idx+1:])
	metricPart := strings.TrimSpace(line[:idx])

	value, err := parseValue(valueStr)
	if err != nil {
		return "", nil, 0, err
	}

	// Parse name and labels
	name, labels := parseNameAndLabels(metricPart)
	return name, labels, value, nil
}

func parseNameAndLabels(s string) (string, []LabelPair) {
	idx := strings.Index(s, "{")
	if idx == -1 {
		return s, nil
	}

	name := s[:idx]
	labelsStr := s[idx+1 : len(s)-1] // Remove { and }

	var labels []LabelPair
	if labelsStr == "" {
		return name, labels
	}

	// Simple label parsing
	for _, part := range splitLabels(labelsStr) {
		eqIdx := strings.Index(part, "=")
		if eqIdx == -1 {
			continue
		}
		labelName := part[:eqIdx]
		labelValue := part[eqIdx+1:]
		// Remove quotes
		if len(labelValue) >= 2 && labelValue[0] == '"' && labelValue[len(labelValue)-1] == '"' {
			labelValue = labelValue[1 : len(labelValue)-1]
		}
		labels = append(labels, LabelPair{Name: labelName, Value: labelValue})
	}

	return name, labels
}

func splitLabels(s string) []string {
	var result []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' && (i == 0 || s[i-1] != '\\') {
			inQuote = !inQuote
		}
		if c == ',' && !inQuote {
			result = append(result, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(c)
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}

func parseValue(s string) (float64, error) {
	switch s {
	case "+Inf":
		return math.Inf(1), nil
	case "-Inf":
		return math.Inf(-1), nil
	case "NaN":
		return math.NaN(), nil
	default:
		return strconv.ParseFloat(s, 64)
	}
}

func parseMetricType(s string) MetricType {
	switch strings.ToLower(s) {
	case "counter":
		return MetricTypeCounter
	case "gauge":
		return MetricTypeGauge
	case "histogram":
		return MetricTypeHistogram
	case "summary":
		return MetricTypeSummary
	default:
		return MetricTypeUntyped
	}
}

func unescapeHelp(s string) string {
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}
