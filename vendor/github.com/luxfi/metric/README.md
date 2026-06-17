# Lux Metrics Library

`github.com/luxfi/metric` is the native metrics library for Lux. It produces a
scrape-compatible text exposition format and is designed for low overhead in
hot paths.

## Features

- Single, native API for counters, gauges, histograms, summaries, and vectors
- Scrape-compatible text format encoder and HTTP handler
- Registry + gatherer model for composition
- Optional no-op build for benchmark runs (build-tagged swap)

## Installation

```bash
go get github.com/luxfi/metric@latest
```

## Quick Start

```go
package main

import (
	"net/http"

	"github.com/luxfi/metric"
)

func main() {
	m := metric.New("myapp")

	requests := m.NewCounter("requests_total", "Total requests")
	latency := m.NewHistogram("request_seconds", "Request latency (s)", metric.DefBuckets)

	requests.Inc()
	latency.Observe(0.123)

	http.Handle("/metrics", metric.Handler())
	_ = http.ListenAndServe(":8080", nil)
}
```

## Custom Registry

```go
reg := metric.NewRegistry()
m := metric.NewWithRegistry("myapp", reg)

requests := m.NewCounter("requests_total", "Total requests")
requests.Inc()

handler := metric.NewHTTPHandler(reg, metric.HandlerOpts{})
```

## Vector Metrics

```go
m := metric.New("myapp")
byRoute := m.NewCounterVec("requests_total", "Requests by route", []string{"method", "route"})

byRoute.WithLabelValues("GET", "/").Inc()
```

## Metrics Off Build

For benchmark runs, you can swap the entire package to no-op implementations
using build tags. This keeps call sites unchanged while minimizing overhead.

```bash
go test -tags metrics ./...
```

When built without the `metrics` tag, `metric.NewRegistry()` and the package
defaults return no-op implementations. Pre-bind label values in hot paths to
avoid argument construction overhead.
