// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build goexperiment.runtimesecret

// Package secret provides helpers for secure handling of cryptographic key material.
//
// When built with GOEXPERIMENT=runtimesecret, secret key bytes are processed
// inside runtime/secret.Do(), which ensures the memory holding the key material
// is zeroed by the runtime after use and is not visible to core dumps or
// debuggers.
//
// Without the experiment flag, the package provides identical API with no-op
// wrappers so callers do not need build tags.
package secret

import (
	"runtime/secret"
)

// Do executes f inside a runtime/secret context, ensuring any stack-allocated
// secret material in f is securely erased after f returns.
//
// Use this to wrap operations that handle raw private key bytes:
//
//	secret.Do(func() {
//	    key := generateKeyBytes()
//	    defer clear(key)
//	    useKey(key)
//	})
func Do(f func()) {
	secret.Do(f)
}

// Enabled reports whether the runtime secret erasure support is active.
func Enabled() bool {
	return secret.Enabled()
}
