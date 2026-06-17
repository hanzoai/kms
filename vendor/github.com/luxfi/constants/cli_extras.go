// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import "time"

// CLI-specific constants shared across tooling.
const (
	ServerRunFile = "gRPCserver.run"

	SuffixSeparator            = "_"
	SidecarFileName            = "sidecar.json"
	GenesisFileName            = "genesis.json"
	ElasticChainConfigFileName = "elastic_chain_config.json"
	NodeConfigJSONFile         = "node-config.json"
	NodeConfigFileName         = "node-config.json"
	ClusterYAMLFileName        = "cluster.yaml"
	ClustersConfigFileName     = "clusters.json"
	LocalNetworkMetaFile       = "local_network_meta.json"
	LastFileName               = ".last_actions.json"
	CertSuffix                 = ".pem"
	AliasesFileName            = "aliases.json"
	YAMLSuffix                 = ".yml"
	SidecarSuffix              = SuffixSeparator + SidecarFileName
	GenesisSuffix              = SuffixSeparator + GenesisFileName
	NodeFileName               = "node.json"

	SidecarVersion             = "1.4.0"
	LatestPreReleaseVersionTag = "latest-prerelease"
	LatestReleaseVersionTag    = "latest"

	MaxLogFileSize   = 4
	MaxNumOfLogFiles = 5
	RetainOldFiles   = 0 // retain all old log files

	// RequestTimeout lives in paths.go; keep CLI-specific timeouts here.
	E2ERequestTimeout            = 30 * time.Second
	ANRRequestTimeout            = 15 * time.Second
	APIRequestLargeTimeout       = 30 * time.Second
	DefaultWalletCreationTimeout = 5 * time.Second
	DefaultConfirmTxTimeout      = 20 * time.Second

	SimulatePublicNetwork    = "SIMULATE_PUBLIC_NETWORK"
	GithubAPITokenEnvVarName = "LUX_CLI_GITHUB_TOKEN"

	// LPM / CLI dependency URLs
	DefaultLuxPackage      = "luxfi/plugins-core"
	CLIMinVersionURL       = "https://raw.githubusercontent.com/luxfi/cli/main/min-version.json"
	CLILatestDependencyURL = CLIMinVersionURL
	LuxdCompatibilityURL   = LuxCompatibilityURL

	// Default values for relayer and validators
	DefaultRelayerAmount  = float64(10)
	PayTxsFeesMsg         = "pay transaction fees"
	LatestEVMVersion      = "v0.8.13"
	DefaultStakeWeight    = 20
	DefaultConfigFileName = ".lux"
	DefaultConfigFileType = "json"

	// Metrics
	MetricsNetwork            = "network"
	MetricsAPITokenEnvVarName = "METRICS_API_TOKEN"

	// Cloud service constants
	GCPCloudService            = "gcp"
	AWSCloudService            = "aws"
	E2EDocker                  = "e2e-docker"
	E2EClusterName             = "e2e-test-cluster"
	E2ENetworkPrefix           = "10.0.0"
	E2EBaseDirName             = ".e2e-test"
	AnsibleInventoryDir        = "ansible/inventory"
	GCPNodeAnsiblePrefix       = "gcp_node"
	AWSNodeAnsiblePrefix       = "aws_node"
	E2EDockerLoopbackHost      = "127.0.0.1"
	GCPDefaultImageProvider    = "canonical"
	GCPImageFilter             = "ubuntu-os-cloud"
	CloudNodeCLIConfigBasePath = "/home/ubuntu/.lux"
	CodespaceNameEnvVar        = "CODESPACE_NAME"
	AnsibleSSHShellParams      = "-o StrictHostKeyChecking=no"
	RemoteSSHUser              = "ubuntu"
	StakerCertFileName         = "staker.crt"
	StakerKeyFileName          = "staker.key"
	BLSKeyFileName             = "bls.key"
	RingtailKeyFileName        = "ringtail.key"
	MLDSAKeyFileName           = "mldsa.key"
	ValidatorUptimeDeductible  = 5 * time.Minute

	// SSH constants
	SSHSleepBetweenChecks = 1 * time.Second
	SSHFileOpsTimeout     = 10 * time.Second
	SSHScriptTimeout      = 120 * time.Second
	SSHPOSTTimeout        = 30 * time.Second
	SSHDirOpsTimeout      = 30 * time.Second

	// Docker constants
	DockerNodeConfigPath   = "/data/.luxgo/configs"
	WriteReadUserOnlyPerms = 0o600

	// AWS constants
	AWSCloudServerRunningState = "running"

	// this depends on bootstrap snapshot
	DefaultTokenName = "TEST"

	DefaultNumberOfLocalMachineNodes = 5

	// Staking constants
	BootstrapValidatorBalanceNanoLUX = 1_000_000_000_000 // 1000 LUX
	BootstrapValidatorWeight         = 20                // Default validator weight
	PoSL1MinimumStakeDurationSeconds = 86400             // 24 hours
	StakingMinimumLeadTime           = 25 * time.Second

	// Logging
	DefaultAggregatorLogLevel = "INFO"

	// Git
	GitExtension       = ".git"
	GitRepoCommitName  = "Lux CLI"
	GitRepoCommitEmail = "info@lux.network"

	// Ansible
	AnsibleHostInventoryFileName = "hosts"
	AnsibleSSHUseAgentParams     = "-o ForwardAgent=yes"

	// Cloud node
	CloudNodeConfigPath           = "/home/ubuntu/.luxgo/configs"
	CloudNodePrometheusConfigPath = "/home/ubuntu/.luxgo/configs/prometheus"
	CloudNodeStakingPath          = "/home/ubuntu/.luxgo/staking"
	UpgradeFileName               = "upgrade.json"
	UpgradeBytesFileName          = "upgrade.json"
	NodePrometheusConfigFileName  = "prometheus.yml"
	ServicesDir                   = "services"
	WarpRelayerInstallDir         = "warp-relayer"
	WarpRelayerConfigFilename     = "warp-relayer.yml"

	// Config keys
	ConfigSnapshotsAutoSaveKey    = "SnapshotsAutoSaveEnabled"
	ConfigUpdatesDisabledKey      = "UpdatesDisabled"
	ConfigMetricsUserIDKey        = "metrics-user-id"
	ConfigMetricsEnabledKey       = "metrics-enabled"
	ConfigAuthorizeCloudAccessKey = "authorize-cloud-access"

	// Build environment
	BuildEnvGolangVersion = "1.24.5"

	// Docker images and repos
	LuxdDockerImage = NodeDockerImage
	LuxdGitRepo     = NodeGitURL
	LuxdRepoName    = NodeRepoName

	// Install directories
	LuxInstallDir     = "lux"
	LuxNodeInstallDir = "luxd"
	LuxGoInstallDir   = "luxd" // Deprecated: use LuxNodeInstallDir
	EVMInstallDir     = "evm"
	WarpDir           = "warp"
	WarpBranch        = "main"
	WarpURL           = "https://github.com/luxfi/warp.git"
	VMDir             = "vms"

	// CLI-specific directories (not in shared constants)
	CurrentPluginDir = "current" // Active plugins symlinked here (under PluginDir)
	DashboardsDir    = "dashboards"
	ChainConfigDir   = "chains"

	// Unified chain config file names (used in ~/.lux/chains/<chainName>/)
	ChainConfigFile         = "config.json"  // Chain-specific config (eth-apis, etc.)
	UnifiedChainGenesisFile = "genesis.json" // Chain genesis
	UnifiedChainUpgradeFile = "upgrade.json" // Chain upgrades
	ChainChainConfigFile    = "chain.json"   // Chain/validator config for the chain

	// Network structure: ~/.lux/networks/<networkName>/runs/<runID>/
	// This keeps network state persistent across runs
	NetworkRunsDir = "runs"

	// CLI commands / toggles
	Enable         = "enable"
	Disable        = "disable"
	SkipUpdateFlag = "skip-update-check"

	// CLI install URL
	CliInstallationURL     = "https://raw.githubusercontent.com/luxfi/cli/main/scripts/install.sh"
	EVMRPCCompatibilityURL = "https://raw.githubusercontent.com/luxfi/evm/main/compatibility.json"

	// Default node RPC URL
	DefaultNodeRunURL = "http://127.0.0.1:9630"

	// Warp addresses
	DefaultWarpMessengerAddress      = "0x0000000000000000000000000000000000000005"
	MainnetCChainWarpRegistryAddress = "0x0000000000000000000000000000000000000006"

	// Devnet flags
	DevnetFlagsProposerVMUseCurrentHeight = true

	// Per-node chain config
	PerNodeChainConfigFileName = "per-node-chain.json"

	// Grafana
	CustomGrafanaDashboardJSON = "custom_dashboard.json"

	// Cloud node paths
	CloudNodeEVMBinaryPath = "/home/ubuntu/.cli/bin/evm"
)
