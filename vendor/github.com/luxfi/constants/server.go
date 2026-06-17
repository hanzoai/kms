// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import "time"

// lux-server gRPC ports for multi-network support
// Each network type has dedicated ports to allow simultaneous operation
// All 4 networks (mainnet, testnet, devnet, custom) can run in parallel
// - mainnet, testnet, devnet: proper public networks (can run locally with validators)
// - local: for local development with chainID 1337 ("custom" is deprecated alias)
// Port scheme: aligned with chain IDs (8368-8371 for gRPC, 8378-8381 for gateway)
const (
	// gRPC server ports (lux-server) - aligned with chain ID pattern
	GRPCPortTestnet = 8368 // testnet gRPC server (chain ID 96368)
	GRPCPortMainnet = 8369 // mainnet gRPC server (chain ID 96369)
	GRPCPortDevnet  = 8370 // devnet gRPC server (chain ID 96370)
	GRPCPortCustom  = 8371 // custom network gRPC server (chainID 1337)
	GRPCPortDev     = 8546 // dev mode gRPC server (Anvil-compatible, HTTP on 8545)

	// Aliases for backward compatibility
	// "custom" is deprecated, use "local" instead
	GRPCPortLocal        = GRPCPortCustom        // canonical; GRPCPortCustom is the deprecated alias
	GRPCGatewayPortLocal = GRPCGatewayPortCustom // canonical; GRPCGatewayPortCustom is the deprecated alias

	// Gateway ports - offset by 10 from gRPC
	GRPCGatewayPortTestnet = 8378 // testnet gateway
	GRPCGatewayPortMainnet = 8379 // mainnet gateway
	GRPCGatewayPortDevnet  = 8380 // devnet gateway
	GRPCGatewayPortCustom  = 8381 // custom gateway
	GRPCGatewayPortDev     = 8556 // dev mode gateway

	// Node API base ports
	NodePortMainnet = 9630 // mainnet first node API port
	NodePortTestnet = 9640 // testnet first node API port
	NodePortDevnet  = 9650 // devnet first node API port
	NodePortCustom  = 9660 // custom network first node API port (chainID 1337)
	NodePortDev     = 8545 // dev mode single-node (Anvil-compatible)

	// gRPC client configuration
	GRPCClientLogLevel = "error"
	GRPCDialTimeout    = 5 * time.Second // Reduced for faster local development
)

// NetworkGRPCPorts holds gRPC port configuration for a network type
type NetworkGRPCPorts struct {
	Server  int
	Gateway int
}

// NetworkPorts holds all port configuration for a network type
type NetworkPorts struct {
	GRPC      int // lux-server gRPC port
	Gateway   int // lux-server gateway port
	NodeBase  int // First node API port (each node uses 2 ports)
	NetworkID uint32
}

// GetGRPCPorts returns the gRPC ports for a given network type
func GetGRPCPorts(networkType string) NetworkGRPCPorts {
	switch networkType {
	case "mainnet":
		return NetworkGRPCPorts{Server: GRPCPortMainnet, Gateway: GRPCGatewayPortMainnet}
	case "testnet":
		return NetworkGRPCPorts{Server: GRPCPortTestnet, Gateway: GRPCGatewayPortTestnet}
	case "devnet":
		return NetworkGRPCPorts{Server: GRPCPortDevnet, Gateway: GRPCGatewayPortDevnet}
	case "dev":
		return NetworkGRPCPorts{Server: GRPCPortDev, Gateway: GRPCGatewayPortDev}
	case "local", "custom": // "custom" is deprecated alias for "local"
		return NetworkGRPCPorts{Server: GRPCPortCustom, Gateway: GRPCGatewayPortCustom}
	default:
		// Default to custom ports for unknown network types
		return NetworkGRPCPorts{Server: GRPCPortCustom, Gateway: GRPCGatewayPortCustom}
	}
}

// GetNetworkStateFile returns the state file name for a network type
// Each network has its own state file to allow parallel operation
func GetNetworkStateFile(networkType string) string {
	switch networkType {
	case "mainnet":
		return "mainnet_network_state.json"
	case "testnet":
		return "testnet_network_state.json"
	case "devnet":
		return "devnet_network_state.json"
	case "dev":
		return "dev_network_state.json"
	case "local", "custom": // "custom" is deprecated alias for "local"
		return "custom_network_state.json"
	default:
		return networkType + "_network_state.json"
	}
}

// ValidNetworkTypes returns all valid network types
// mainnet, testnet, devnet: proper public networks (can also run locally)
// custom: for custom local development with chainID 1337
// dev: single-node Anvil-compatible mode on port 8545
func ValidNetworkTypes() []string {
	return []string{"mainnet", "testnet", "devnet", "custom", "dev"}
}

// IsValidNetworkType checks if the network type is valid
func IsValidNetworkType(networkType string) bool {
	for _, valid := range ValidNetworkTypes() {
		if networkType == valid {
			return true
		}
	}
	return false
}

// GetNetworkPorts returns all port configuration for a network type
func GetNetworkPorts(networkType string) NetworkPorts {
	switch networkType {
	case "mainnet":
		return NetworkPorts{
			GRPC:      GRPCPortMainnet,
			Gateway:   GRPCGatewayPortMainnet,
			NodeBase:  NodePortMainnet,
			NetworkID: MainnetChainID,
		}
	case "testnet":
		return NetworkPorts{
			GRPC:      GRPCPortTestnet,
			Gateway:   GRPCGatewayPortTestnet,
			NodeBase:  NodePortTestnet,
			NetworkID: TestnetChainID,
		}
	case "devnet":
		return NetworkPorts{
			GRPC:      GRPCPortDevnet,
			Gateway:   GRPCGatewayPortDevnet,
			NodeBase:  NodePortDevnet,
			NetworkID: 96370, // devnet network ID
		}
	case "dev":
		return NetworkPorts{
			GRPC:      GRPCPortDev,
			Gateway:   GRPCGatewayPortDev,
			NodeBase:  NodePortDev,
			NetworkID: CustomID, // 1337 for dev mode (Anvil-compatible)
		}
	case "local", "custom": // "custom" is deprecated alias for "local"
		return NetworkPorts{
			GRPC:      GRPCPortCustom,
			Gateway:   GRPCGatewayPortCustom,
			NodeBase:  NodePortCustom,
			NetworkID: CustomID, // 1337 for custom development
		}
	default:
		return NetworkPorts{
			GRPC:      GRPCPortCustom,
			Gateway:   GRPCGatewayPortCustom,
			NodeBase:  NodePortCustom,
			NetworkID: CustomID,
		}
	}
}
