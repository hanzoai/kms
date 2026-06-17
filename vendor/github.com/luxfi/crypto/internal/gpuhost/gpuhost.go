// Package gpuhost provides the runtime hook between luxfi/crypto algorithm
// packages and github.com/luxfi/accel.
//
// gpuhost owns a singleton accel session and exposes thin helpers that
// algorithm packages call to ask "is GPU available right now?" and to
// fetch the session for batch operations.
//
// gpuhost is internal: callers outside luxfi/crypto must use the public
// dispatchers in each algorithm package, which call gpuhost.
package gpuhost

import (
	"sync"

	"github.com/luxfi/accel"
)

var (
	once     sync.Once
	sess     *accel.Session
	initErr  error
	available bool
)

// Init initialises accel exactly once and creates the shared session.
// Safe to call from any goroutine. Subsequent calls are no-ops.
func Init() {
	once.Do(func() {
		if err := accel.Init(); err != nil {
			initErr = err
			return
		}
		if !accel.Available() {
			return // accel ready but no devices; available stays false
		}
		s, err := accel.NewSession()
		if err != nil {
			initErr = err
			return
		}
		sess = s
		available = true
	})
}

// Available returns true when an accel session was successfully created
// and is currently usable. Algorithm packages check this before deciding
// to dispatch to the GPU path.
func Available() bool {
	Init()
	return available
}

// Session returns the shared accel.Session, or nil if no GPU is available.
// Callers must check Available() first or guard nil at the call site.
func Session() *accel.Session {
	Init()
	return sess
}

// InitError returns the last error from accel initialisation. It is
// non-nil only when the accel library itself failed to load; an
// "accel works, no device" state returns nil.
func InitError() error {
	Init()
	return initErr
}
