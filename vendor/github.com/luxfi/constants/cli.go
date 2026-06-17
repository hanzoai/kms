// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import "time"

// CLI and operational constants (extends paths.go)
const (
	// Remote network API endpoints
	// Each network has: api.lux{-suffix}.network for HTTP, wss.lux{-suffix}.network for WebSocket
	MainnetAPIEndpoint = "https://api.lux.network"
	MainnetWSEndpoint  = "wss://wss.lux.network"
	TestnetAPIEndpoint = "https://api.lux-test.network"
	TestnetWSEndpoint  = "wss://wss.lux-test.network"
	DevnetAPIEndpoint  = "https://api.lux-dev.network"
	DevnetWSEndpoint   = "wss://wss.lux-dev.network"

	// Local network (single-node dev mode or 5-node localnet)
	LocalAPIEndpoint        = "http://127.0.0.1:9630"
	LocalWSEndpoint         = "ws://127.0.0.1:9630/ext/bc/C/ws"
	LocalNetworkID          = LocalID // 1337
	NetrunnerLocalNetworkID = LocalID // 1337
	LocalNetworkNumNodes    = 5

	// Staking constants
	MinStakeDuration     = 24 * 14 * time.Hour  // 2 weeks
	MaxStakeDuration     = 24 * 365 * time.Hour // 1 year
	MinStakeWeight       = uint64(1)
	StakingStartLeadTime = 1 * time.Minute
	TimeParseLayout      = "2006-01-02 15:04:05"

	// Version management
	LuxCompatibilityURL = "https://raw.githubusercontent.com/luxfi/cli/main/lux-compatibility.json"
	DefaultLuxdVersion  = "v1.21.0"
)
