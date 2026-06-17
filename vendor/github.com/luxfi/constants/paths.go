// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import "time"

// Base directory configuration - consistent across node, netrunner, cli
const (
	// BaseDirName is the default directory name for Lux data
	// Located at ~/.lux on all platforms
	BaseDirName = ".lux"
)

// Binary configuration
const (
	// NodeBinaryName is the name of the node binary executable
	NodeBinaryName = "luxd"

	// NodeInstallDir is the subdirectory for node binary under ~/.lux/bin/
	NodeInstallDir = "node"
)

// Snapshot configuration
const (
	// SnapshotPrefix is the prefix for network snapshot directories
	// Full path: ~/.lux/snapshots/lux-snapshot-{name}/
	SnapshotPrefix = "lux-snapshot-"

	// DefaultSnapshotName is the default snapshot name
	DefaultSnapshotName = "default-20251225"

	// Network-specific snapshot names
	MainnetSnapshotName = "mainnet-20251225"
	TestnetSnapshotName = "testnet-20251225"
	DevnetSnapshotName  = "devnet-20251225"
	CustomSnapshotName  = "custom-20251225"
)

// Directory structure
const (
	// BinDir is the subdirectory for binaries
	BinDir = "bin"

	// NetDir is the subdirectory for network data
	NetDir = "net"

	// LuxCliBinDir is an alias for BinDir (backward compatibility with CLI)
	LuxCliBinDir = BinDir

	// SnapshotsDir is the subdirectory for network snapshots
	SnapshotsDir = "snapshots"

	// SnapshotsDirName is an alias for SnapshotsDir
	SnapshotsDirName = SnapshotsDir

	// RunsDir is the subdirectory for runtime data
	RunsDir = "runs"

	// RunDir is an alias for RunsDir (backward compatibility with CLI)
	RunDir = RunsDir

	// PluginsDir is the subdirectory for VM plugins
	PluginsDir = "plugins"

	// PluginDir is an alias for PluginsDir
	PluginDir = PluginsDir

	// LogDir is the subdirectory for logs
	LogDir = "logs"

	// ConfigDir is the subdirectory for configuration
	ConfigDir = "config"

	// KeyDir is the subdirectory for keys
	KeyDir = "keys"

	// ChainsDir is the subdirectory for chain definitions
	ChainsDir = "chains"

	// NetworksDir is the subdirectory for network state
	NetworksDir = "networks"

	// CustomVMDir is the subdirectory for custom VMs
	CustomVMDir = "customvms"

	// ReposDir is the subdirectory for repositories
	ReposDir = "repos"

	// LPMDir is the subdirectory for LPM
	LPMDir = ".lpm"

	// LPMPluginDir is the subdirectory for LPM plugins
	LPMPluginDir = "lpm-plugins"

	// DevDir is the subdirectory for dev mode data
	// Used by 'lux dev start' for single-node development
	DevDir = "dev"
)

// File permissions
const (
	DefaultPerms755            = 0o755
	WriteReadReadPerms         = 0o644
	WriteReadOnlyPerms         = 0o600
	UserOnlyWriteReadExecPerms = 0o700 // User read/write/execute only
)

// File names and extensions
const (
	// ElasticNetConfigFileName is the filename for elastic network config
	ElasticNetConfigFileName = "elastic.json"

	// LPMLogName is the filename for LPM logs
	LPMLogName = "lpm.log"

	// UpgradeBytesLockExtension is the lock file extension for upgrade bytes
	UpgradeBytesLockExtension = ".lock"
)

// API + WebSocket endpoints are defined in cli.go (single source of truth).
// Pattern:
//   mainnet: api.lux.network / wss.lux.network
//   testnet: api.lux-test.network / wss.lux-test.network
//   devnet:  api.lux-dev.network / wss.lux-dev.network
//   local:   127.0.0.1:9650

// Default ports
const (
	// DefaultHTTPPort is the default HTTP API port
	DefaultHTTPPort = 9630

	// DefaultStakingPort is the default staking/P2P port
	DefaultStakingPort = 9631
)

// Timeouts
const (
	RequestTimeout    = 3 * time.Minute
	APIRequestTimeout = 30 * time.Second
)
