// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !unix && !windows

package metric

func processCPUSeconds() (float64, bool) {
	return 0, false
}

func processResidentBytes() (float64, bool) {
	return 0, false
}
