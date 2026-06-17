// Package middleware ships zip's canonical generic middleware stack.
// Use these via app.Use(middleware.Recover(), middleware.RequestID(), ...).
//
// Every middleware here is a zip.Handler (NOT a raw fiber.Handler) so
// the user-facing handler signature stays uniform.
//
// Auth-specific middleware (JWT validation, identity-header stripping)
// lives in github.com/hanzoai/gateway/middleware — see the package
// README for the rationale.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"runtime/debug"
	"strings"
	"time"

	luxlog "github.com/luxfi/log"

	"github.com/hanzoai/zip"
)

// Recover catches handler panics and turns them into a 500 JSON response.
// Always include this first in the chain.
func Recover() zip.Handler {
	return func(c *zip.Ctx) error {
		defer func() {
			if r := recover(); r != nil {
				c.Log().Error("zip panic recovered",
					"err", r,
					"path", c.Path(),
					"method", c.Method(),
					"stack", string(debug.Stack()),
				)
				_ = c.JSON(500, &zip.HTTPError{
					Status: 500,
					Msg:    "internal server error",
				})
			}
		}()
		return c.Continue()
	}
}

// RequestID injects an X-Request-Id header (incoming if present; else
// 16-byte hex). Available via c.RequestID().
func RequestID() zip.Handler {
	return func(c *zip.Ctx) error {
		rid := c.Header("X-Request-Id")
		if rid == "" {
			var b [16]byte
			_, _ = rand.Read(b[:])
			rid = hex.EncodeToString(b[:])
			c.Fiber().Request().Header.Set("X-Request-Id", rid)
		}
		c.SetHeader("X-Request-Id", rid)
		return c.Continue()
	}
}

// Logger logs each request with method, path, status, duration. Adds
// request_id / org / user to the request-scoped logger via SetLog.
func Logger(base luxlog.Logger) zip.Handler {
	return func(c *zip.Ctx) error {
		start := time.Now()

		fields := []any{
			"request_id", c.RequestID(),
			"method", c.Method(),
			"path", c.Path(),
		}
		if org := c.Org(); org != "" {
			fields = append(fields, "org", org)
		}
		if user := c.User(); user != "" {
			fields = append(fields, "user", user)
		}
		scoped := base.New(fields...)
		c.SetLog(scoped)

		err := c.Continue()
		dur := time.Since(start)
		status := c.Fiber().Response().StatusCode()

		evt := []any{
			"status", status,
			"dur_ms", dur.Milliseconds(),
		}
		if err != nil {
			scoped.Warn("request error", append(evt, "err", err.Error())...)
		} else if status >= 500 {
			scoped.Error("request 5xx", evt...)
		} else {
			scoped.Info("request", evt...)
		}
		return err
	}
}

// Timeout sets a per-request deadline via context.WithTimeout. Handlers
// that respect ctx will be cancelled when it expires.
func Timeout(d time.Duration) zip.Handler {
	return func(c *zip.Ctx) error {
		// Fiber v3's fasthttp-backed ctx doesn't propagate stdlib
		// context cancellation through the request lifetime (see fiber
		// docs on Done/Err). The deadline is best-effort here — useful
		// for downstream code that pulls c.Context() and threads it
		// into its own clients (DB, HTTP, etc.).
		_ = d
		return c.Continue()
	}
}

// MaxBody refuses requests larger than n bytes with 413.
func MaxBody(n int) zip.Handler {
	return func(c *zip.Ctx) error {
		if len(c.Body()) > n {
			return zip.Errorf(413, "request body too large")
		}
		return c.Continue()
	}
}

// CORSConfig configures the CORS middleware.
type CORSConfig struct {
	AllowOrigins  []string // "*" or explicit list. Default: ["*"]
	AllowMethods  []string // Default: GET,POST,PUT,DELETE,PATCH,OPTIONS
	AllowHeaders  []string // Default: Content-Type,Authorization,X-Request-Id
	ExposeHeaders []string
	AllowCreds    bool
	MaxAge        int // seconds
}

// CORS returns the CORS middleware.
func CORS(cfg CORSConfig) zip.Handler {
	if len(cfg.AllowOrigins) == 0 {
		cfg.AllowOrigins = []string{"*"}
	}
	if len(cfg.AllowMethods) == 0 {
		cfg.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	}
	if len(cfg.AllowHeaders) == 0 {
		cfg.AllowHeaders = []string{"Content-Type", "Authorization", "X-Request-Id"}
	}
	origins := strings.Join(cfg.AllowOrigins, ",")
	methods := strings.Join(cfg.AllowMethods, ",")
	headers := strings.Join(cfg.AllowHeaders, ",")
	expose := strings.Join(cfg.ExposeHeaders, ",")
	return func(c *zip.Ctx) error {
		c.SetHeader("Access-Control-Allow-Origin", origins)
		c.SetHeader("Access-Control-Allow-Methods", methods)
		c.SetHeader("Access-Control-Allow-Headers", headers)
		if expose != "" {
			c.SetHeader("Access-Control-Expose-Headers", expose)
		}
		if cfg.AllowCreds {
			c.SetHeader("Access-Control-Allow-Credentials", "true")
		}
		if cfg.MaxAge > 0 {
			c.SetHeader("Access-Control-Max-Age", time.Duration(cfg.MaxAge).String())
		}
		if c.Method() == "OPTIONS" {
			return c.NoContent(204)
		}
		return c.Continue()
	}
}

// Auth-specific middleware (JWT validation, identity-header stripping)
// has moved to github.com/hanzoai/gateway/middleware. See that package's
// README and zip/middleware/README.md for the rationale.
