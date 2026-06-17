# Lux Metrics Library (AI Notes)

This package provides the native metrics system for Lux. It does not depend on
external metrics clients and emits a scrape-compatible text format.

## Core Concepts

- **Registry**: collects metrics and implements `Gatherer`.
- **Metrics**: namespace-scoped factories created via `metric.New(namespace)`.
- **Handlers**: `metric.Handler()` and `metric.NewHTTPHandler(reg, opts)` expose text output.

## Primary APIs

```go
reg := metric.NewRegistry()
m := metric.NewWithRegistry("myapp", reg)

reqs := m.NewCounter("requests_total", "Total requests")
latency := m.NewHistogram("request_seconds", "Request latency", metric.DefBuckets)

reqs.Inc()
latency.Observe(0.123)
```

Vector metrics:

```go
byRoute := m.NewCounterVec("requests_total", "Requests by route", []string{"method", "route"})
byRoute.WithLabelValues("GET", "/").Inc()
```

## Text Format

Use `metric.EncodeText(w, families)` to serialize gathered metrics, or
`metric.Handler()` / `metric.NewHTTPHandler(...)` to serve metrics over HTTP.

## Metrics-Off Build

The package supports build-tagged no-op defaults. When compiled without
the `metrics` tag, `NewRegistry` and the package defaults return no-op
implementations to minimize overhead. Pre-bind label values in hot paths to
avoid expensive argument construction.
