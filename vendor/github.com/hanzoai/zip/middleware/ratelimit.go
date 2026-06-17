package middleware

import (
	"sync"
	"time"

	"github.com/hanzoai/zip"
)

// RateLimitConfig configures the per-key token bucket.
type RateLimitConfig struct {
	// Limit is the number of requests permitted per Window.
	Limit int
	// Window is the time window (e.g. 1*time.Minute).
	Window time.Duration
	// KeyFn extracts the bucket key from the request. Default: c.Org()
	// if present, else c.Fiber().IP().
	KeyFn func(c *zip.Ctx) string
}

// RateLimit returns a per-org (or per-IP fallback) token-bucket limiter.
// Buckets are kept in-memory; suitable for single-pod deployments.
// Multi-pod deployments should use a distributed limiter at the gateway.
func RateLimit(cfg RateLimitConfig) zip.Handler {
	if cfg.Limit <= 0 {
		cfg.Limit = 100
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.KeyFn == nil {
		cfg.KeyFn = func(c *zip.Ctx) string {
			if org := c.Org(); org != "" {
				return org
			}
			return c.Fiber().IP()
		}
	}

	type bucket struct {
		count int
		reset time.Time
	}
	var (
		mu      sync.Mutex
		buckets = map[string]*bucket{}
	)

	return func(c *zip.Ctx) error {
		key := cfg.KeyFn(c)
		now := time.Now()

		mu.Lock()
		b, ok := buckets[key]
		if !ok || now.After(b.reset) {
			b = &bucket{reset: now.Add(cfg.Window)}
			buckets[key] = b
		}
		b.count++
		remaining := cfg.Limit - b.count
		exhausted := b.count > cfg.Limit
		mu.Unlock()

		if exhausted {
			c.SetHeader("X-RateLimit-Limit", itoa(cfg.Limit))
			c.SetHeader("X-RateLimit-Remaining", "0")
			return zip.Errorf(429, "rate limit exceeded")
		}
		c.SetHeader("X-RateLimit-Limit", itoa(cfg.Limit))
		c.SetHeader("X-RateLimit-Remaining", itoa(remaining))
		return c.Continue()
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
