// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

// gRPC backend server command names.
const (
	// LuxServerCmd is the base command name for the gRPC backend server.
	// Network-specific variants: lux-mainnet-grpc, lux-testnet-grpc, etc.
	LuxServerCmd = "lux-server"
	// BackendCmd is deprecated, use LuxServerCmd instead.
	BackendCmd = LuxServerCmd

	LuxMainnetGRPCCmd = "lux-mainnet-grpc"
	LuxTestnetGRPCCmd = "lux-testnet-grpc"
	LuxDevnetGRPCCmd  = "lux-devnet-grpc"
	LuxCustomGRPCCmd  = "lux-custom-grpc"
)

// GetServerCmdForNetwork returns the network-specific gRPC server command name.
func GetServerCmdForNetwork(networkType string) string {
	switch networkType {
	case "mainnet":
		return LuxMainnetGRPCCmd
	case "testnet":
		return LuxTestnetGRPCCmd
	case "devnet":
		return LuxDevnetGRPCCmd
	case "local", "custom":
		return LuxCustomGRPCCmd
	default:
		return LuxServerCmd
	}
}
