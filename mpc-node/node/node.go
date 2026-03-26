// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

// Package node implements the MPC node lifecycle: initialization, starting,
// stopping, and CRDT synchronization with peers.
package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"google.golang.org/grpc"

	"github.com/hanzoai/kms/mpc-node/compliance"
	mpcCrypto "github.com/hanzoai/kms/mpc-node/crypto"
	mpcFHE "github.com/hanzoai/kms/mpc-node/fhe"
	"github.com/hanzoai/kms/mpc-node/shard"
	"github.com/hanzoai/kms/mpc-node/store"
)

// Node is a single MPC node in the distributed KMS cluster.
type Node struct {
	ID         string
	Config     *Config
	Compliance *compliance.Engine

	Store  *store.Store
	Shards *shard.ShardManager   // nil for TierStandard
	CRDT   *mpcFHE.CRDTSync     // nil unless TierTFHE or TierSovereign
	Peers  []string

	grpcServer *grpc.Server
	mu         sync.Mutex
	running    bool
	logger     *slog.Logger
}

// NewNode creates a new MPC node from configuration.
// Subsystem initialization is tier-dependent:
//   - TierStandard:  store only (server-side encryption, no MPC)
//   - TierMPC:       store + shard manager (Shamir threshold)
//   - TierTFHE:      store + shard manager + FHE CRDT
//   - TierSovereign: store + shard manager + FHE CRDT (SessionVM stubbed)
func NewNode(cfg *Config) (*Node, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("node: invalid config: %w", err)
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return nil, fmt.Errorf("node: create data dir: %w", err)
	}

	s, err := store.NewStore(cfg.ZapDBPath(), cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("node: open store: %w", err)
	}

	logger := slog.Default().With("node", cfg.NodeID, "tier", cfg.Tier.String())

	n := &Node{
		ID:     cfg.NodeID,
		Config: cfg,
		Store:  s,
		Peers:  cfg.Peers,
		logger: logger,
	}

	// Shard manager for MPC tiers and above.
	if cfg.Tier.RequiresMPC() {
		sm, err := shard.NewShardManager(s, cfg.NodeID, cfg.Threshold, cfg.TotalNodes)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("node: shard manager: %w", err)
		}
		n.Shards = sm
	}

	// FHE CRDT only for TFHE and Sovereign tiers.
	// Evaluator initialization requires FHE bootstrap keys which are provided
	// at ceremony time — the CRDT field is set later via InitFHE().

	// Compliance engine (nil for ModeNone).
	ce, err := compliance.NewEngine(cfg.Compliance, s)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("node: compliance engine: %w", err)
	}
	n.Compliance = ce

	logger.Info("node initialized", "tier", cfg.Tier.String())
	return n, nil
}

// Bootstrap initializes a new org's key material on this node.
// For TierMPC and above, it derives a master key from the passphrase,
// splits it into shards, and stores this node's shard locally.
// For TierStandard, bootstrap is a no-op (server-side key management).
func (n *Node) Bootstrap(orgSlug, passphrase string, nodeIndex int) (*shard.BootstrapResult, error) {
	if !n.Config.Tier.RequiresMPC() {
		return nil, errors.New("node: bootstrap requires mpc tier or above")
	}

	n.logger.Info("bootstrapping org", "org", orgSlug, "tier", n.Config.Tier.String(),
		"threshold", n.Config.Threshold, "nodes", n.Config.TotalNodes)

	masterKey, err := mpcCrypto.DeriveCEK(passphrase, []byte(orgSlug))
	if err != nil {
		return nil, fmt.Errorf("node: derive master key: %w", err)
	}

	result, err := n.Shards.BootstrapCeremony(orgSlug, masterKey, nodeIndex)
	if err != nil {
		return nil, fmt.Errorf("node: bootstrap ceremony: %w", err)
	}

	n.logger.Info("bootstrap complete", "org", orgSlug, "shards", len(result.Shards))
	return result, nil
}

// Join accepts a shard from a bootstrap or rotation ceremony and stores it locally.
func (n *Node) Join(orgSlug string, shardData []byte) error {
	if !n.Config.Tier.RequiresMPC() {
		return errors.New("node: join requires mpc tier or above")
	}
	n.logger.Info("joining org", "org", orgSlug)
	return n.Shards.InviteNode(orgSlug, shardData)
}

// InitFHE sets the FHE CRDT sync engine. Only valid for TierTFHE and TierSovereign.
// Called after FHE bootstrap keys are available (post-ceremony).
func (n *Node) InitFHE(crdt *mpcFHE.CRDTSync) error {
	if !n.Config.Tier.RequiresFHE() {
		return fmt.Errorf("node: FHE initialization requires tfhe tier or above, got %s", n.Config.Tier)
	}
	n.CRDT = crdt
	n.logger.Info("FHE CRDT initialized")
	return nil
}

// Serve starts the gRPC server on the configured listen address.
func (n *Node) Serve(ctx context.Context) error {
	n.mu.Lock()
	if n.running {
		n.mu.Unlock()
		return errors.New("node: already running")
	}

	lis, err := net.Listen("tcp", n.Config.ListenAddr)
	if err != nil {
		n.mu.Unlock()
		return fmt.Errorf("node: listen %s: %w", n.Config.ListenAddr, err)
	}

	n.grpcServer = grpc.NewServer()
	// gRPC service registration happens in api/grpc.go
	n.running = true
	n.mu.Unlock()

	n.logger.Info("serving", "addr", n.Config.ListenAddr)

	// Run server in a goroutine so we can handle context cancellation.
	errCh := make(chan error, 1)
	go func() {
		errCh <- n.grpcServer.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		n.logger.Info("shutting down gRPC server")
		n.grpcServer.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

// Sync triggers CRDT synchronization with all peers.
// Requires TierTFHE or above — MPC tier uses direct shard exchange, not CRDT.
// This is a best-effort operation; failures are logged but do not stop the node.
func (n *Node) Sync(orgSlug string) error {
	if !n.Config.Tier.RequiresFHE() {
		return fmt.Errorf("node: CRDT sync requires tfhe tier or above, got %s", n.Config.Tier)
	}
	if n.CRDT == nil {
		return errors.New("node: CRDT sync not initialized (call InitFHE first)")
	}
	var syncErrors []error
	for _, peer := range n.Peers {
		n.logger.Info("syncing with peer", "peer", peer, "org", orgSlug)
		if err := n.CRDT.SyncWithPeer(peer, orgSlug); err != nil {
			n.logger.Error("sync failed", "peer", peer, "error", err)
			syncErrors = append(syncErrors, fmt.Errorf("peer %s: %w", peer, err))
		}
	}
	if len(syncErrors) > 0 {
		return fmt.Errorf("node: %d sync failures", len(syncErrors))
	}
	return nil
}

// Shutdown gracefully stops the node.
func (n *Node) Shutdown() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.logger.Info("shutdown requested")

	if n.grpcServer != nil {
		n.grpcServer.GracefulStop()
	}
	n.running = false

	if n.Store != nil {
		return n.Store.Close()
	}
	return nil
}

// GRPCServer returns the underlying gRPC server for service registration.
func (n *Node) GRPCServer() *grpc.Server {
	return n.grpcServer
}
