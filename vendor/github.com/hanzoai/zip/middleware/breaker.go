package middleware

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/hanzoai/zip"
)

// BreakerState is the externally observable state of a circuit breaker.
type BreakerState int32

const (
	// BreakerClosed allows traffic. Failures are counted toward the trip
	// threshold.
	BreakerClosed BreakerState = iota
	// BreakerOpen rejects every request with 503 until the open window
	// elapses, at which point the breaker transitions to half-open.
	BreakerOpen
	// BreakerHalfOpen permits one request at a time. A success closes
	// the breaker; a failure re-opens it.
	BreakerHalfOpen
)

// BreakerConfig configures a single circuit breaker. The breaker is a
// composable middleware: failures are anything that returns a non-nil
// error OR writes a 5xx status. The "target" abstraction is the
// caller's — wrap one breaker per upstream where you want isolation.
type BreakerConfig struct {
	// FailureThreshold is the number of consecutive failures (or the
	// failure count within the rolling window) that trips the breaker.
	// Default: 5.
	FailureThreshold int

	// SuccessThreshold is the number of consecutive successes in
	// half-open that closes the breaker. Default: 1 (the first
	// half-open success closes immediately).
	SuccessThreshold int

	// OpenWindow is how long the breaker stays open before transitioning
	// to half-open. Default: 5s.
	OpenWindow time.Duration

	// FailureClassifier classifies an outcome as a failure. By default a
	// non-nil handler error OR a 5xx response body is a failure.
	FailureClassifier func(err error, status int) bool

	// Now is the clock. Inject for tests. Default: time.Now.
	Now func() time.Time

	// OnStateChange, if set, is called every time the breaker transitions.
	// Useful for metrics. Called from the breaker's critical section, so
	// the callback MUST NOT block.
	OnStateChange func(prev, next BreakerState)
}

// Breaker is one circuit-breaker instance. Safe for concurrent use.
//
// Breaker is intentionally per-process: it is a memoized recent-failure
// view, not a coordinated cross-replica policy. N replicas of the same
// service running their own breaker is the correct shape — each replica
// sheds load it cannot serve. There is no shared state, no leader, no
// coordination overhead.
type Breaker struct {
	cfg BreakerConfig

	mu              sync.Mutex
	state           BreakerState
	consecFailures  int
	consecSuccesses int
	openedAt        time.Time

	// halfOpenInFlight bounds concurrent requests in half-open to 1.
	halfOpenInFlight atomic.Bool

	// Metrics
	totalRequests   atomic.Uint64
	totalShortCircs atomic.Uint64
	totalFailures   atomic.Uint64
	totalSuccesses  atomic.Uint64
}

// NewBreaker constructs a Breaker with defaults applied.
func NewBreaker(cfg BreakerConfig) *Breaker {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = 1
	}
	if cfg.OpenWindow <= 0 {
		cfg.OpenWindow = 5 * time.Second
	}
	if cfg.FailureClassifier == nil {
		cfg.FailureClassifier = defaultFailureClassifier
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Breaker{cfg: cfg, state: BreakerClosed}
}

// State returns the breaker's current state. Cheap; lock-free.
func (b *Breaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maybeTransitionLocked(b.cfg.Now())
	return b.state
}

// Stats is a snapshot of the breaker's counters. Cheap; lock-free.
type Stats struct {
	State          BreakerState
	Requests       uint64
	ShortCircuited uint64
	Failures       uint64
	Successes      uint64
}

// Stats returns a counter snapshot. Useful for /metrics exposition.
func (b *Breaker) Stats() Stats {
	return Stats{
		State:          b.State(),
		Requests:       b.totalRequests.Load(),
		ShortCircuited: b.totalShortCircs.Load(),
		Failures:       b.totalFailures.Load(),
		Successes:      b.totalSuccesses.Load(),
	}
}

// Allow reports whether the breaker permits a new request right now.
// Callers that need to wrap arbitrary code (not a zip handler) can use
// this directly and then call Report(err, status) when the work
// completes.
//
// In half-open state, Allow returns true for exactly one in-flight
// request; subsequent callers see false until the in-flight one
// reports.
func (b *Breaker) Allow() bool {
	b.totalRequests.Add(1)
	b.mu.Lock()
	now := b.cfg.Now()
	b.maybeTransitionLocked(now)
	switch b.state {
	case BreakerClosed:
		b.mu.Unlock()
		return true
	case BreakerOpen:
		b.mu.Unlock()
		b.totalShortCircs.Add(1)
		return false
	case BreakerHalfOpen:
		b.mu.Unlock()
		if b.halfOpenInFlight.CompareAndSwap(false, true) {
			return true
		}
		b.totalShortCircs.Add(1)
		return false
	}
	b.mu.Unlock()
	return false
}

// Report records the outcome of a request that previously Allow()ed.
// err is the handler error; status is the final response status. The
// breaker uses cfg.FailureClassifier to decide whether it was a
// failure.
func (b *Breaker) Report(err error, status int) {
	isFail := b.cfg.FailureClassifier(err, status)
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case BreakerClosed:
		if isFail {
			b.consecFailures++
			b.totalFailures.Add(1)
			if b.consecFailures >= b.cfg.FailureThreshold {
				b.setStateLocked(BreakerOpen)
				b.openedAt = b.cfg.Now()
			}
		} else {
			b.consecFailures = 0
			b.totalSuccesses.Add(1)
		}
	case BreakerHalfOpen:
		b.halfOpenInFlight.Store(false)
		if isFail {
			b.totalFailures.Add(1)
			b.setStateLocked(BreakerOpen)
			b.openedAt = b.cfg.Now()
			b.consecSuccesses = 0
		} else {
			b.consecSuccesses++
			b.totalSuccesses.Add(1)
			if b.consecSuccesses >= b.cfg.SuccessThreshold {
				b.setStateLocked(BreakerClosed)
				b.consecFailures = 0
				b.consecSuccesses = 0
			}
		}
	case BreakerOpen:
		// Spurious report (Allow returned false but caller reported anyway)
		// — ignore. The open window is the only thing that moves us out.
	}
}

func (b *Breaker) maybeTransitionLocked(now time.Time) {
	if b.state == BreakerOpen && now.Sub(b.openedAt) >= b.cfg.OpenWindow {
		b.setStateLocked(BreakerHalfOpen)
		b.consecSuccesses = 0
	}
}

func (b *Breaker) setStateLocked(next BreakerState) {
	prev := b.state
	if prev == next {
		return
	}
	b.state = next
	if cb := b.cfg.OnStateChange; cb != nil {
		cb(prev, next)
	}
}

// defaultFailureClassifier treats handler errors and 5xx statuses as
// failures. 4xx is the caller's fault and does not trip the breaker.
func defaultFailureClassifier(err error, status int) bool {
	if err != nil {
		return true
	}
	return status >= 500
}

// Breaker returns the zip middleware form of b. The middleware:
//
//  1. Calls b.Allow() before delegating to the next handler.
//  2. If Allow returns false, short-circuits with 503 and a brief
//     {"error":"upstream unavailable"} body. NO retry. NO queue. Fail
//     fast — let the client back off.
//  3. Otherwise runs c.Continue() and reports the outcome.
//
// The breaker is single-purpose: it sheds load when the protected
// resource is in trouble. Combine with other middleware (Logger,
// Recover, Timeout) the usual way.
func (b *Breaker) Middleware() zip.Handler {
	return func(c *zip.Ctx) error {
		if !b.Allow() {
			return zip.Errorf(503, "upstream unavailable")
		}
		err := c.Continue()
		status := c.Fiber().Response().StatusCode()
		b.Report(err, status)
		return err
	}
}
