package log

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	crand "crypto/rand"
	"encoding/binary"
	"math/rand/v2"
)

var (
	// Often samples log every ~ 10 events.
	Often = RandomSampler(10)
	// Sometimes samples log every ~ 100 events.
	Sometimes = RandomSampler(100)
	// Rarely samples log every ~ 1000 events.
	Rarely = RandomSampler(1000)

	// globalRand is a thread-safe random source
	globalRand = newLockedRand()
)

// lockedRand is a thread-safe random number generator
type lockedRand struct {
	mu  sync.Mutex
	rng *rand.Rand
}

func newLockedRand() *lockedRand {
	var seed [8]byte
	_, _ = crand.Read(seed[:])
	src := rand.NewPCG(binary.LittleEndian.Uint64(seed[:]), binary.LittleEndian.Uint64(seed[:]))
	return &lockedRand{rng: rand.New(src)}
}

func (r *lockedRand) Intn(n int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rng.IntN(n)
}

// Sampler defines an interface to a log sampler.
type Sampler interface {
	// Sample returns true if the event should be part of the sample, false if
	// the event should be dropped.
	Sample(lvl Level) bool
}

// RandomSampler use a PRNG to randomly sample an event out of N events,
// regardless of their level.
type RandomSampler uint32

// Sample implements the Sampler interface.
func (s RandomSampler) Sample(lvl Level) bool {
	if s <= 0 {
		return false
	}
	if globalRand.Intn(int(s)) != 0 {
		return false
	}
	return true
}

// BasicSampler is a sampler that will send every Nth events, regardless of
// their level.
type BasicSampler struct {
	N       uint32
	counter uint32
}

// Sample implements the Sampler interface.
func (s *BasicSampler) Sample(lvl Level) bool {
	n := s.N
	if n == 0 {
		return false
	}
	if n == 1 {
		return true
	}
	c := atomic.AddUint32(&s.counter, 1)
	return c%n == 1
}

// BurstSampler lets Burst events pass per Period then pass the decision to
// NextSampler. If Sampler is not set, all subsequent events are rejected.
type BurstSampler struct {
	// Burst is the maximum number of event per period allowed before calling
	// NextSampler.
	Burst uint32
	// Period defines the burst period. If 0, NextSampler is always called.
	Period time.Duration
	// NextSampler is the sampler used after the burst is reached. If nil,
	// events are always rejected after the burst.
	NextSampler Sampler

	counter uint32
	resetAt int64
}

// Sample implements the Sampler interface.
func (s *BurstSampler) Sample(lvl Level) bool {
	if s.Burst > 0 && s.Period > 0 {
		if s.inc() <= s.Burst {
			return true
		}
	}
	if s.NextSampler == nil {
		return false
	}
	return s.NextSampler.Sample(lvl)
}

func (s *BurstSampler) inc() uint32 {
	now := TimestampFunc().UnixNano()
	resetAt := atomic.LoadInt64(&s.resetAt)
	var c uint32
	if now >= resetAt {
		c = 1
		atomic.StoreUint32(&s.counter, c)
		newResetAt := now + s.Period.Nanoseconds()
		reset := atomic.CompareAndSwapInt64(&s.resetAt, resetAt, newResetAt)
		if !reset {
			// Lost the race with another goroutine trying to reset.
			c = atomic.AddUint32(&s.counter, 1)
		}
	} else {
		c = atomic.AddUint32(&s.counter, 1)
	}
	return c
}

// LevelSampler applies a different sampler for each level.
type LevelSampler struct {
	TraceSampler, DebugSampler, InfoSampler, WarnSampler, ErrorSampler Sampler
}

func (s LevelSampler) Sample(lvl Level) bool {
	switch lvl {
	case TraceLevel:
		if s.TraceSampler != nil {
			return s.TraceSampler.Sample(lvl)
		}
	case DebugLevel:
		if s.DebugSampler != nil {
			return s.DebugSampler.Sample(lvl)
		}
	case InfoLevel:
		if s.InfoSampler != nil {
			return s.InfoSampler.Sample(lvl)
		}
	case WarnLevel:
		if s.WarnSampler != nil {
			return s.WarnSampler.Sample(lvl)
		}
	case ErrorLevel:
		if s.ErrorSampler != nil {
			return s.ErrorSampler.Sample(lvl)
		}
	}
	return true
}

// DedupSampler suppresses duplicate log messages within a time window.
// After the window expires, it emits a summary of suppressed messages.
type DedupSampler struct {
	// Window is the deduplication time window. Defaults to 1 minute.
	Window time.Duration
	// MaxKeys is the maximum number of unique messages to track. Defaults to 1000.
	MaxKeys int

	mu      sync.Mutex
	seen    map[uint64]*dedupEntry
	cleanup int64 // next cleanup time (unix nano)
}

type dedupEntry struct {
	count    int64
	firstAt  int64
	lastAt   int64
	lastEmit int64
}

// NewDedupSampler creates a dedup sampler with the given window.
func NewDedupSampler(window time.Duration) *DedupSampler {
	if window <= 0 {
		window = time.Minute
	}
	return &DedupSampler{
		Window:  window,
		MaxKeys: 1000,
		seen:    make(map[uint64]*dedupEntry),
	}
}

// SampleMsg returns true if this message should be logged.
// It tracks message hashes and suppresses duplicates within the window.
func (s *DedupSampler) SampleMsg(lvl Level, msg string) bool {
	return s.SampleMsgWithKey(lvl, msg, "")
}

// SampleMsgWithKey allows specifying a custom dedup key instead of using msg.
func (s *DedupSampler) SampleMsgWithKey(lvl Level, msg, key string) bool {
	if key == "" {
		key = msg
	}

	// Hash the level + message for dedup key
	h := fnv.New64a()
	h.Write([]byte{byte(lvl)})
	h.Write([]byte(key))
	hash := h.Sum64()

	now := TimestampFunc().UnixNano()
	windowNano := s.Window.Nanoseconds()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Lazy init
	if s.seen == nil {
		s.seen = make(map[uint64]*dedupEntry)
	}

	// Periodic cleanup of old entries
	if now > s.cleanup {
		s.cleanupLocked(now, windowNano)
		s.cleanup = now + windowNano
	}

	entry, exists := s.seen[hash]
	if !exists {
		// First time seeing this message
		if len(s.seen) >= s.MaxKeys {
			// Evict oldest entry if at capacity
			s.evictOldestLocked()
		}
		s.seen[hash] = &dedupEntry{
			count:    1,
			firstAt:  now,
			lastAt:   now,
			lastEmit: now,
		}
		return true
	}

	// Update stats
	entry.count++
	entry.lastAt = now

	// Check if window has expired since last emit
	if now-entry.lastEmit >= windowNano {
		entry.lastEmit = now
		return true
	}

	// Suppress this message
	return false
}

// Sample implements the Sampler interface (always returns true for non-dedup use).
func (s *DedupSampler) Sample(lvl Level) bool {
	return true
}

// GetSuppressedCount returns the count of suppressed messages for a key.
func (s *DedupSampler) GetSuppressedCount(lvl Level, msg string) int64 {
	h := fnv.New64a()
	h.Write([]byte{byte(lvl)})
	h.Write([]byte(msg))
	hash := h.Sum64()

	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.seen[hash]; exists {
		return entry.count - 1 // exclude the one we emitted
	}
	return 0
}

func (s *DedupSampler) cleanupLocked(now, windowNano int64) {
	cutoff := now - windowNano
	for hash, entry := range s.seen {
		if entry.lastAt < cutoff {
			delete(s.seen, hash)
		}
	}
}

func (s *DedupSampler) evictOldestLocked() {
	var oldestHash uint64
	var oldestTime int64 = 1<<63 - 1
	for hash, entry := range s.seen {
		if entry.lastAt < oldestTime {
			oldestTime = entry.lastAt
			oldestHash = hash
		}
	}
	if oldestHash != 0 {
		delete(s.seen, oldestHash)
	}
}
