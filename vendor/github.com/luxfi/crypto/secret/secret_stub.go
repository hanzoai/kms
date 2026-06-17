// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !goexperiment.runtimesecret

package secret

// Do executes f directly. Without GOEXPERIMENT=runtimesecret, this is a
// pass-through with no runtime secret memory protection.
//
// Callers should still clear(key) sensitive byte slices manually.
func Do(f func()) {
	f()
}

// Enabled reports whether the runtime secret erasure support is active.
// Returns false when built without GOEXPERIMENT=runtimesecret.
func Enabled() bool {
	return false
}
