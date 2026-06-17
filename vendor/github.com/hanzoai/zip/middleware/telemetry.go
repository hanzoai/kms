package middleware

import (
	"time"

	"github.com/hanzoai/zip"
)

// O11ySink is the minimum interface zip's telemetry middleware consumes.
// Real implementations live in hanzoai/insights / o11y SDKs. nil sink =
// no-op middleware.
type O11ySink interface {
	// Record reports a single request to the o11y backend.
	Record(method, path string, status int, dur time.Duration, attrs map[string]string)
}

// Telemetry returns middleware that records every request through sink.
// Use this alongside Logger() (which writes to luxfi/log); Telemetry()
// is for structured metrics/traces flowing to o11y backends.
func Telemetry(sink O11ySink) zip.Handler {
	if sink == nil {
		return func(c *zip.Ctx) error { return c.Continue() }
	}
	return func(c *zip.Ctx) error {
		start := time.Now()
		err := c.Continue()
		dur := time.Since(start)
		attrs := map[string]string{}
		if rid := c.RequestID(); rid != "" {
			attrs["request_id"] = rid
		}
		if org := c.Org(); org != "" {
			attrs["org"] = org
		}
		sink.Record(c.Method(), c.Path(), c.Fiber().Response().StatusCode(), dur, attrs)
		return err
	}
}
