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

// Tracing bootstrap — this is the ONE way a Hanzo Go daemon emits spans: one
// call, one service name, so the console's per-product Monitoring tab (which
// filters by service name) lights up for this product.
//
// Spans travel to o11y over ZAP, luxfi/trace's native transport: a JSON
// SpanBatch inside a ZAP envelope, read by hanzo/o11y/pkg/zapreceiver. There is
// no OTLP, no protobuf and no gRPC anywhere in this path — the exporter that
// carried them is gone from luxfi/trace, which is why this binary's module
// graph no longer contains google.golang.org/grpc.
//
// Opt-in via O11Y_ENDPOINT and non-fatal in every failure mode, so this is safe
// to ship before a collector is live: New() does not dial, and the batch
// processor exports in the background, so boot never blocks on o11y.
package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/luxfi/trace"
)

// The collector's ZAP address in-cluster. Set O11Y_ENDPOINT to "default" to take
// this rather than repeating it in every deployment.
const defaultO11yEndpoint = "o11y.hanzo.svc:4317"

// initTelemetry installs the tracer for serviceName and returns a shutdown func
// that flushes and stops it. The returned func is ALWAYS non-nil, so callers
// defer it unconditionally. An operator may override serviceName at runtime with
// O11Y_SERVICE_NAME.
func initTelemetry(_ context.Context, serviceName string) func(context.Context) {
	endpoint := firstNonEmptyEnv("O11Y_TRACES_ENDPOINT", "O11Y_ENDPOINT")
	if endpoint == "" {
		log.Printf("telemetry: disabled (set O11Y_ENDPOINT to emit spans to o11y)")
		return func(context.Context) {}
	}
	if endpoint == "default" {
		endpoint = defaultO11yEndpoint
	}
	if v := strings.TrimSpace(os.Getenv("O11Y_SERVICE_NAME")); v != "" {
		serviceName = v
	}

	tracer, err := trace.New(trace.Config{
		ExporterConfig: trace.ExporterConfig{
			Type:     trace.ZAP,
			Endpoint: endpoint,
		},
		TraceSampleRate: 1,
		AppName:         serviceName,
	})
	if err != nil {
		log.Printf("telemetry: create ZAP trace exporter: %v", err)
		return func(context.Context) {}
	}
	log.Printf("telemetry: spans -> o11y over ZAP at %s (service=%s)", endpoint, serviceName)

	return func(context.Context) {
		// Tracer.Close carries its own shutdown deadline.
		if err := tracer.Close(); err != nil {
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
