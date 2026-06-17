// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import (
	"sync"

	"github.com/luxfi/ids"
)

// ChainConfig holds the chain IDs for a specific network.
// This allows chain IDs to be dynamically configured per network,
// enabling migration to new chain IDs without code changes.
type ChainConfig struct {
	NetworkID uint32

	PChainID ids.ID // Platform chain - staking, validation
	XChainID ids.ID // Exchange chain - UTXO asset exchange
	CChainID ids.ID // Contract chain - EVM smart contracts
	QChainID ids.ID // Quantum chain - post-quantum cryptography
	AChainID ids.ID // Attestation chain - oracles, compute attestation
	BChainID ids.ID // Bridge chain - cross-chain interop
	TChainID ids.ID // Threshold chain - FHE, threshold crypto
	ZChainID ids.ID // ZK chain - zero-knowledge proofs
	GChainID ids.ID // Graph chain - dgraph
	KChainID ids.ID // KMS chain - key management
	DChainID ids.ID // DEX chain - native DEX
}

// ChainRegistry provides dynamic lookup of chain IDs per network.
// It supports runtime configuration and migration of chain IDs.
type ChainRegistry struct {
	mu      sync.RWMutex
	configs map[uint32]*ChainConfig

	// Callbacks for chain ID migration events
	onMigrate []func(networkID uint32, oldConfig, newConfig *ChainConfig)
}

// DefaultRegistry is the global chain registry with default configurations.
var DefaultRegistry = NewChainRegistry()

func init() {
	// Initialize default configurations for known networks
	DefaultRegistry.RegisterConfig(defaultMainnetConfig())
	DefaultRegistry.RegisterConfig(defaultTestnetConfig())
	DefaultRegistry.RegisterConfig(defaultDevnetConfig())
	DefaultRegistry.RegisterConfig(defaultCustomConfig())
}

// NewChainRegistry creates a new chain registry.
func NewChainRegistry() *ChainRegistry {
	return &ChainRegistry{
		configs: make(map[uint32]*ChainConfig),
	}
}

// RegisterConfig registers a chain configuration for a network.
func (r *ChainRegistry) RegisterConfig(config *ChainConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.configs[config.NetworkID] = config
}

// GetConfig returns the chain configuration for a network.
// Returns nil if no configuration exists.
func (r *ChainRegistry) GetConfig(networkID uint32) *ChainConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.configs[networkID]
}

// GetOrDefault returns the chain configuration for a network,
// or the default (mainnet) configuration if not found.
func (r *ChainRegistry) GetOrDefault(networkID uint32) *ChainConfig {
	if config := r.GetConfig(networkID); config != nil {
		return config
	}
	// Fall back to mainnet defaults with overridden NetworkID
	config := defaultMainnetConfig()
	config.NetworkID = networkID
	return config
}

// MigrateChain updates a chain ID for a network.
// This triggers migration callbacks and is used for chain upgrades.
func (r *ChainRegistry) MigrateChain(networkID uint32, chainName string, newChainID ids.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	config, exists := r.configs[networkID]
	if !exists {
		return ErrNetworkNotFound
	}

	oldConfig := *config // Copy for callback

	switch chainName {
	case "P", "platform":
		config.PChainID = newChainID
	case "X", "exchange":
		config.XChainID = newChainID
	case "C", "contract":
		config.CChainID = newChainID
	case "Q", "quantum":
		config.QChainID = newChainID
	case "A", "attestation":
		config.AChainID = newChainID
	case "B", "bridge":
		config.BChainID = newChainID
	case "T", "threshold":
		config.TChainID = newChainID
	case "Z", "zk":
		config.ZChainID = newChainID
	case "D", "dex":
		config.DChainID = newChainID
	default:
		return ErrUnknownChain
	}

	// Notify migration callbacks
	for _, callback := range r.onMigrate {
		callback(networkID, &oldConfig, config)
	}

	return nil
}

// OnMigrate registers a callback for chain migration events.
func (r *ChainRegistry) OnMigrate(callback func(networkID uint32, oldConfig, newConfig *ChainConfig)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onMigrate = append(r.onMigrate, callback)
}

// Convenience methods for accessing chain IDs

// GetPChainID returns the P-chain ID for the given network.
func (r *ChainRegistry) GetPChainID(networkID uint32) ids.ID {
	return r.GetOrDefault(networkID).PChainID
}

// GetXChainID returns the X-chain ID for the given network.
func (r *ChainRegistry) GetXChainID(networkID uint32) ids.ID {
	return r.GetOrDefault(networkID).XChainID
}

// GetCChainID returns the C-chain ID for the given network.
func (r *ChainRegistry) GetCChainID(networkID uint32) ids.ID {
	return r.GetOrDefault(networkID).CChainID
}

// GetQChainID returns the Q-chain ID for the given network.
func (r *ChainRegistry) GetQChainID(networkID uint32) ids.ID {
	return r.GetOrDefault(networkID).QChainID
}

// GetAChainID returns the A-chain ID for the given network.
func (r *ChainRegistry) GetAChainID(networkID uint32) ids.ID {
	return r.GetOrDefault(networkID).AChainID
}

// GetBChainID returns the B-chain ID for the given network.
func (r *ChainRegistry) GetBChainID(networkID uint32) ids.ID {
	return r.GetOrDefault(networkID).BChainID
}

// GetTChainID returns the T-chain ID for the given network.
func (r *ChainRegistry) GetTChainID(networkID uint32) ids.ID {
	return r.GetOrDefault(networkID).TChainID
}

// GetZChainID returns the Z-chain ID for the given network.
func (r *ChainRegistry) GetZChainID(networkID uint32) ids.ID {
	return r.GetOrDefault(networkID).ZChainID
}

// GetDChainID returns the D-chain ID for the given network.
func (r *ChainRegistry) GetDChainID(networkID uint32) ids.ID {
	return r.GetOrDefault(networkID).DChainID
}

// Default configurations for each network

func defaultMainnetConfig() *ChainConfig {
	return &ChainConfig{
		NetworkID: MainnetID,
		PChainID:  ids.PChainID,
		XChainID:  ids.XChainID,
		CChainID:  ids.CChainID,
		QChainID:  ids.QChainID,
		AChainID:  ids.AChainID,
		BChainID:  ids.BChainID,
		TChainID:  ids.TChainID,
		ZChainID:  ids.ZChainID,
		DChainID:  ids.DChainID,
	}
}

func defaultTestnetConfig() *ChainConfig {
	return &ChainConfig{
		NetworkID: TestnetID,
		PChainID:  ids.PChainID,
		XChainID:  ids.XChainID,
		CChainID:  ids.CChainID,
		QChainID:  ids.QChainID,
		AChainID:  ids.AChainID,
		BChainID:  ids.BChainID,
		TChainID:  ids.TChainID,
		ZChainID:  ids.ZChainID,
		DChainID:  ids.DChainID,
	}
}

func defaultDevnetConfig() *ChainConfig {
	return &ChainConfig{
		NetworkID: DevnetID,
		PChainID:  ids.PChainID,
		XChainID:  ids.XChainID,
		CChainID:  ids.CChainID,
		QChainID:  ids.QChainID,
		AChainID:  ids.AChainID,
		BChainID:  ids.BChainID,
		TChainID:  ids.TChainID,
		ZChainID:  ids.ZChainID,
		DChainID:  ids.DChainID,
	}
}

func defaultCustomConfig() *ChainConfig {
	return &ChainConfig{
		NetworkID: CustomID,
		PChainID:  ids.PChainID,
		XChainID:  ids.XChainID,
		CChainID:  ids.CChainID,
		QChainID:  ids.QChainID,
		AChainID:  ids.AChainID,
		BChainID:  ids.BChainID,
		TChainID:  ids.TChainID,
		ZChainID:  ids.ZChainID,
		DChainID:  ids.DChainID,
	}
}

// Package-level convenience functions using DefaultRegistry

// GetChainConfig returns the chain configuration for a network.
func GetChainConfig(networkID uint32) *ChainConfig {
	return DefaultRegistry.GetOrDefault(networkID)
}

// GetNetworkPChainID returns the P-chain ID for the given network.
func GetNetworkPChainID(networkID uint32) ids.ID {
	return DefaultRegistry.GetPChainID(networkID)
}

// GetNetworkXChainID returns the X-chain ID for the given network.
func GetNetworkXChainID(networkID uint32) ids.ID {
	return DefaultRegistry.GetXChainID(networkID)
}

// GetNetworkCChainID returns the C-chain ID for the given network.
func GetNetworkCChainID(networkID uint32) ids.ID {
	return DefaultRegistry.GetCChainID(networkID)
}

// GetNetworkQChainID returns the Q-chain ID for the given network.
func GetNetworkQChainID(networkID uint32) ids.ID {
	return DefaultRegistry.GetQChainID(networkID)
}
