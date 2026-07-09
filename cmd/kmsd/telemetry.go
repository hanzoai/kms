// Copyright 2023-2026 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// OTel telemetry bootstrap — installs the global tracer provider that ships this
// service's spans to the shared o11y backend over OTLP. This is the ONE
// way a Hanzo Go daemon emits OpenTelemetry: one call, one service.name, so the
// console's per-product Monitoring tab (which filters by service.name) lights up
// for this product.
//
// Posture mirrors the ai module (ai/object/telemetry.go): opt-in via
// OTEL_EXPORTER_OTLP_ENDPOINT, non-fatal, and a clean no-op when the endpoint is
// unset — SAFE to ship before the collector is live. The OTLP HTTP exporter
// self-configures from the standard OTEL_EXPORTER_OTLP_* env (endpoint, headers,
// per-scheme TLS, timeout) — never hard-coded; New() does not dial and the batch
// span processor exports in the background, so boot never blocks on the collector.
package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// initTelemetry installs the global OTel tracer provider for serviceName and
// returns a shutdown func that flushes and stops the exporter. The returned func
// is ALWAYS non-nil, so callers defer it unconditionally. An operator may
// override serviceName at runtime with OTEL_SERVICE_NAME.
func initTelemetry(ctx context.Context, serviceName string) func(context.Context) {
	endpoint := firstNonEmptyEnv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		log.Printf("telemetry: disabled (set OTEL_EXPORTER_OTLP_ENDPOINT to emit OTel spans to o11y)")
		return func(context.Context) {}
	}
	if v := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); v != "" {
		serviceName = v
	}
	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		log.Printf("telemetry: create OTLP trace exporter: %v", err)
		return func(context.Context) {}
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", serviceName))),
	)
	otel.SetTracerProvider(tp)
	log.Printf("telemetry: OTel spans -> o11y via OTLP (service.name=%s)", serviceName)
	return func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(ctx); err != nil {
			log.Printf("telemetry: shutdown: %v", err)
		}
	}
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}
