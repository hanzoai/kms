// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

// Organization and repository names
const (
	// LuxOrg is the GitHub organization
	LuxOrg = "luxfi"

	// Repository names
	NodeRepoName      = "node"
	EVMRepoName       = "evm"
	NetrunnerRepoName = "netrunner"
	CLIRepoName       = "cli"
	CliRepoName       = CLIRepoName
	ConstantsRepoName = "constants"
	SDKRepoName       = "sdk"
	WalletRepoName    = "wallet"

	// Aliases for backward compatibility
	LuxRepoName = NodeRepoName // deprecated: use NodeRepoName
)

// Binary names
const (
	// NodeBinaryName is the name of the node executable
	// Already defined in paths.go, keeping here for reference
	// NodeBinaryName = "luxd"

	// NetrunnerBinaryName is the name of the netrunner executable
	NetrunnerBinaryName = "netrunner"

	// EVMBinaryName is the name of the EVM plugin
	EVMBinaryName = "evm"
	// EVMBin is a compatibility alias for EVMBinaryName.
	EVMBin = EVMBinaryName

	// CLIBinaryName is the name of the CLI executable
	CLIBinaryName = "lux"
)

// Docker images
const (
	NodeDockerImage = "luxfi/luxd"
	EVMDockerImage  = "luxfi/evm"
)

// Git URLs
const (
	NodeGitURL      = "https://github.com/luxfi/node"
	EVMGitURL       = "https://github.com/luxfi/evm"
	NetrunnerGitURL = "https://github.com/luxfi/netrunner"
	CLIGitURL       = "https://github.com/luxfi/cli"
)

// Environment variables for binary paths
const (
	EnvNodePath      = "LUX_NODE_PATH"
	EnvNetrunnerPath = "LUX_NETRUNNER_PATH"
	EnvEVMPath       = "LUX_EVM_PATH"
	EnvPluginsDir    = "LUX_PLUGINS_DIR"
)

// Config keys for binary paths (viper/config file keys)
const (
	ConfigNodePath      = "node-path"
	ConfigNetrunnerPath = "netrunner-path"
	ConfigEVMPath       = "evm-path"
	ConfigPluginsDir    = "plugins-dir"
)
