// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
)

// Const variables to be exported
const (
	// Network IDs (P-Chain) - these identify the PRIMARY NETWORK
	// mainnet, testnet, devnet: proper public networks (can run locally with validators)
	// Network IDs (P-Chain) — identify the primary network
	MainnetID  uint32 = 1    // Production
	TestnetID  uint32 = 2    // Staging
	DevnetID   uint32 = 3    // Development
	LocalID    uint32 = 1337 // Local single/multi-node dev
	UnitTestID uint32 = 369

	// Backward compat aliases
	LuxMainnetID = MainnetID
	LuxTestnetID = TestnetID
	CustomID     = LocalID // deprecated: use LocalID

	// Chain IDs (C-Chain EVM) — for wallets/dApps
	MainnetChainID uint32 = 96369
	TestnetChainID uint32 = 96368
	DevnetChainID  uint32 = 96370
	LocalChainID   uint32 = 1337
	CustomChainID  = LocalChainID // deprecated: use LocalChainID

	// Q-Chain Network IDs
	QChainMainnetID uint32 = 36963
	QChainTestnetID uint32 = 36962

	// Network name strings
	MainnetName  = "mainnet"
	TestnetName  = "testnet"
	DevnetName   = "devnet"
	LocalName    = "local"
	CustomName   = LocalName // deprecated: use LocalName
	UnitTestName = "testing"

	// HRP (Human Readable Part) for bech32 addresses
	// Determines address prefix: P-lux1..., X-test1..., P-local1...
	MainnetHRP  = "lux"   // P-lux1..., X-lux1...
	TestnetHRP  = "test"  // P-test1..., X-test1...
	DevnetHRP   = "dev"   // P-dev1..., X-dev1...
	LocalHRP    = "local"  // P-local1..., X-local1... (network 1337)
	CustomHRP   = "custom" // P-custom1..., X-custom1... (any other network ID)
	UnitTestHRP = "testing"
)

// Variables to be exported
var (
	PrimaryNetworkID = ids.Empty
	PlatformChainID  = ids.PChainID // P-Chain: 11111111111111111111111111111111P

	// Chain IDs - these identify specific chains WITHIN a network
	// NOT to be confused with Network IDs
	// Native chains have a recognizable pattern: all zeros except last byte which is the chain letter
	// These are provided by the ids package for consistent display across the ecosystem
	CChainID = ids.CChainID // C-Chain: 11111111111111111111111111111111C
	XChainID = ids.XChainID // X-Chain: 11111111111111111111111111111111X
	QChainID = ids.QChainID // Q-Chain: 11111111111111111111111111111111Q
	AChainID = ids.AChainID // A-Chain: 11111111111111111111111111111111A
	BChainID = ids.BChainID // B-Chain: 11111111111111111111111111111111B
	TChainID = ids.TChainID // T-Chain: 11111111111111111111111111111111T
	ZChainID = ids.ZChainID // Z-Chain: 11111111111111111111111111111111Z (Zero-knowledge)
	GChainID = ids.GChainID // G-Chain: 11111111111111111111111111111111G (Graph/dgraph)
	KChainID = ids.KChainID // K-Chain: 11111111111111111111111111111111K (KMS)
	DChainID = ids.DChainID // D-Chain: 11111111111111111111111111111111D (DEX)

	// NetworkIDToNetworkName maps network IDs to human-readable names
	NetworkIDToNetworkName = map[uint32]string{
		MainnetID:      MainnetName, // 1
		TestnetID:      TestnetName, // 2
		DevnetID:       DevnetName,  // 3
		LocalID:        LocalName,   // 1337
		UnitTestID:     UnitTestName,
		MainnetChainID: MainnetName,
		TestnetChainID: TestnetName,
		DevnetChainID:  DevnetName,
	}

	// NetworkNameToNetworkID maps names to network IDs
	NetworkNameToNetworkID = map[string]uint32{
		MainnetName:  MainnetID,
		TestnetName:  TestnetID,
		DevnetName:   DevnetID,
		LocalName:    LocalID,
		"custom":     LocalID, // backward compat
		UnitTestName: UnitTestID,
	}

	// NetworkIDToHRP maps network IDs to bech32 address prefix
	// 1 → P-lux1..., 2 → P-test1..., 3 → P-dev1..., 1337 → P-local1...
	// Unknown network IDs fall back to "custom" HRP
	NetworkIDToHRP = map[uint32]string{
		MainnetID:      MainnetHRP,  // lux
		TestnetID:      TestnetHRP,  // test
		DevnetID:       DevnetHRP,   // dev
		LocalID:        LocalHRP,    // local
		UnitTestID:     UnitTestHRP,
		MainnetChainID: MainnetHRP,
		TestnetChainID: TestnetHRP,
		DevnetChainID:  DevnetHRP,
	}

	// NetworkHRPToNetworkID maps HRP back to network ID
	NetworkHRPToNetworkID = map[string]uint32{
		MainnetHRP:  MainnetID,
		TestnetHRP:  TestnetID,
		DevnetHRP:   DevnetID,
		LocalHRP:    LocalID,
		"custom":    LocalID, // backward compat
		UnitTestHRP: UnitTestID,
	}

	// ProductionNetworkIDs are networks that should use production-grade settings
	ProductionNetworkIDs = set.Of(MainnetID, TestnetID, MainnetChainID, TestnetChainID)

	ValidNetworkPrefix = "network-"

	ErrParseNetworkName = errors.New("failed to parse network name")
	ErrNetworkNotFound  = errors.New("network not found in registry")
	ErrUnknownChain     = errors.New("unknown chain name")
)

// GetHRP returns the Human-Readable-Part of bech32 addresses for a networkID
func GetHRP(networkID uint32) string {
	if hrp, ok := NetworkIDToHRP[networkID]; ok {
		return hrp
	}
	return CustomHRP // fallback for unknown/custom network IDs (not 1/2/3/1337)
}

// NetworkName returns a human readable name for the network with
// ID [networkID]
func NetworkName(networkID uint32) string {
	if name, exists := NetworkIDToNetworkName[networkID]; exists {
		return name
	}
	return fmt.Sprintf("network-%d", networkID)
}

// NetworkID returns the ID of the network with name [networkName]
func NetworkID(networkName string) (uint32, error) {
	networkName = strings.ToLower(networkName)
	if id, exists := NetworkNameToNetworkID[networkName]; exists {
		return id, nil
	}

	idStr := networkName
	if strings.HasPrefix(networkName, ValidNetworkPrefix) {
		idStr = networkName[len(ValidNetworkPrefix):]
	}
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrParseNetworkName, networkName)
	}
	return uint32(id), nil
}
