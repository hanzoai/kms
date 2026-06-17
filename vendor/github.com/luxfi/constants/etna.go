// Copyright (C) 2022-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import "time"

// EtnaActivationTime provides network activation times for Etna.
var EtnaActivationTime = map[uint32]time.Time{
	TestnetID:      time.Date(2024, time.November, 25, 16, 0, 0, 0, time.UTC),
	MainnetID:      time.Date(2024, time.December, 16, 17, 0, 0, 0, time.UTC),
	LocalNetworkID: time.Unix(0, 0), // Local networks activate immediately (Unix epoch)
}
