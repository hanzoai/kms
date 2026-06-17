// Copyright (C) 2022-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import "time"

// CLI/infra roles.
const (
	APIRole         = "api"
	ValidatorRole   = "validator"
	MonitorRole     = "monitor"
	WarpRelayerRole = "warp-relayer"
)

// HTTPAccess represents HTTP access configuration.
type HTTPAccess string

const (
	HTTPAccessPublic  HTTPAccess = "public"
	HTTPAccessPrivate HTTPAccess = "private"
)

// Key file suffixes.
const (
	KeySuffix = ".pk"
)

// Default ports used by tooling.
const (
	SSHTCPPort         = 22
	LuxdAPIPort        = 9630
	LuxdP2PPort        = 9651
	LuxdMonitoringPort = 9090
	LuxdGrafanaPort    = 3000
	LuxdLokiPort       = 23101
)

// Cloud/infra timeouts and limits.
const (
	SSHLongRunningScriptTimeout      = 10 * time.Minute
	CloudOperationTimeout            = 5 * time.Minute
	CloudServerStorageSize           = 100 // GB
	MonitoringCloudServerStorageSize = 200 // GB
	GCPStaticIPPrefix                = "lux-"
	IPAddressSuffix                  = "-ip"
	ErrReleasingGCPStaticIP          = "error releasing GCP static IP"
)
