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

	mpcCrypto "github.com/hanzoai/kms/mpc-node/crypto"
	mpcFHE "github.com/hanzoai/kms/mpc-node/fhe"
	"github.com/hanzoai/kms/mpc-node/shard"
	"github.com/hanzoai/kms/mpc-node/store"
)

// Node is a single MPC node in the distributed KMS cluster.
type Node struct {
	ID     string
	Config *Config

	Store  *store.Store
	Shards *shard.ShardManager
	CRDT   *mpcFHE.CRDTSync
	Peers  []string

	grpcServer *grpc.Server
	mu         sync.Mutex
	running    bool
	logger     *slog.Logger
}

// NewNode creates a new MPC node from configuration.
// It initializes the local ZapDB store and shard manager but does not start serving.
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

	sm, err := shard.NewShardManager(s, cfg.NodeID, cfg.Threshold, cfg.TotalNodes)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("node: shard manager: %w", err)
	}

	logger := slog.Default().With("node", cfg.NodeID)

	return &Node{
		ID:     cfg.NodeID,
		Config: cfg,
		Store:  s,
		Shards: sm,
		Peers:  cfg.Peers,
		logger: logger,
	}, nil
}

// Bootstrap initializes a new org's key material on this node.
// It derives a master key from the passphrase, splits it into shards,
// and stores this node's shard locally.
func (n *Node) Bootstrap(orgSlug, passphrase string, nodeIndex int) (*shard.BootstrapResult, error) {
	n.logger.Info("bootstrapping org", "org", orgSlug, "threshold", n.Config.Threshold, "nodes", n.Config.TotalNodes)

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
	n.logger.Info("joining org", "org", orgSlug)
	return n.Shards.InviteNode(orgSlug, shardData)
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
// This is a best-effort operation; failures are logged but do not stop the node.
func (n *Node) Sync(orgSlug string) error {
	if n.CRDT == nil {
		return errors.New("node: CRDT sync not initialized")
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
