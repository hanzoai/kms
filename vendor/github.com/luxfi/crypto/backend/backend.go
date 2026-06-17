// Package backend defines the runtime backend selector for luxfi/crypto.
//
// Every crypto package in this module has up to three implementations:
//
//   - vanilla: pure-Go reference (always available)
//   - cgo:     native C library binding (blst, libsecp256k1, ckzg, ...)
//   - gpu:     batch acceleration via github.com/luxfi/accel
//
// The package selects which implementation to run based on the value of
// Default(). Callers can override programmatically with SetDefault(),
// or globally with the CRYPTO_BACKEND environment variable.
//
// The default value is Auto — pick the most capable backend the binary
// was compiled and linked with, in the order GPU > CGo > Vanilla.
package backend

import (
	"os"
	"strings"
	"sync/atomic"
)

// Backend identifies a crypto implementation choice.
type Backend uint32

const (
	// Auto selects the best available backend automatically.
	Auto Backend = iota
	// Vanilla forces the pure-Go reference implementation.
	Vanilla
	// CGo forces the native C-library backed implementation when available.
	CGo
	// GPU forces routing through github.com/luxfi/accel when available.
	GPU
)

// String returns the canonical lowercase name of the backend.
func (b Backend) String() string {
	switch b {
	case Auto:
		return "auto"
	case Vanilla:
		return "vanilla"
	case CGo:
		return "cgo"
	case GPU:
		return "gpu"
	default:
		return "unknown"
	}
}

// Parse converts a string identifier to a Backend. Empty string returns Auto.
func Parse(s string) (Backend, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return Auto, true
	case "vanilla", "go", "pure":
		return Vanilla, true
	case "cgo", "c", "native":
		return CGo, true
	case "gpu", "accel":
		return GPU, true
	default:
		return Auto, false
	}
}

var current uint32 // atomic Backend

// envBackend reads CRYPTO_BACKEND from the environment.
func envBackend() (string, bool) {
	return os.LookupEnv("CRYPTO_BACKEND")
}

func init() {
	if v, ok := envBackend(); ok {
		if b, parsed := Parse(v); parsed {
			atomic.StoreUint32(&current, uint32(b))
		}
	}
}

// Default returns the active backend selection. The value is Auto unless
// SetDefault was called or CRYPTO_BACKEND was set in the environment.
func Default() Backend {
	return Backend(atomic.LoadUint32(&current))
}

// SetDefault overrides the active backend.
//
// Use the empty string or "auto" via Parse to revert to Auto behavior.
func SetDefault(b Backend) {
	atomic.StoreUint32(&current, uint32(b))
}

// Available is reserved for backend probing. Today, Auto and Vanilla are
// always available; CGo and GPU are reported by build-tagged shims and the
// runtime resolver.
func Available(b Backend) bool {
	switch b {
	case Auto, Vanilla:
		return true
	default:
		return false
	}
}

// Resolve picks a concrete backend for the caller. If Default() is Auto the
// resolution falls back through GPU → CGo → Vanilla, choosing the first
// backend reported as available by the supplied probes. probes may be nil;
// in that case Resolve returns Vanilla for Auto.
//
// This is the primary entry point used inside algorithm packages:
//
//	switch backend.Resolve(gpuOK, cgoOK) {
//	case backend.GPU:     return keccak256GPU(in)
//	case backend.CGo:     return keccak256CGo(in)
//	default:              return keccak256Vanilla(in)
//	}
func Resolve(gpuAvailable, cgoAvailable bool) Backend {
	switch d := Default(); d {
	case Vanilla:
		return Vanilla
	case CGo:
		if cgoAvailable {
			return CGo
		}
		return Vanilla
	case GPU:
		if gpuAvailable {
			return GPU
		}
		if cgoAvailable {
			return CGo
		}
		return Vanilla
	default: // Auto
		if gpuAvailable {
			return GPU
		}
		if cgoAvailable {
			return CGo
		}
		return Vanilla
	}
}
