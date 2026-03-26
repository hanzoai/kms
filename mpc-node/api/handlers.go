// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package api

import (
	"context"
	"errors"

	"github.com/hanzoai/kms/mpc-node/node"
	"github.com/hanzoai/kms/mpc-node/store"
)

// Handler implements the gRPC service handlers for the MPC node.
// These map to the proto service definition in api/proto/mpc.proto.
type Handler struct {
	node *node.Node
}

// NewHandler creates a new gRPC handler backed by the given node.
func NewHandler(n *node.Node) *Handler {
	return &Handler{node: n}
}

// StoreShard handles the StoreShard RPC.
func (h *Handler) StoreShard(_ context.Context, orgSlug string, shard []byte) error {
	if orgSlug == "" {
		return errors.New("org_slug is required")
	}
	if len(shard) == 0 {
		return errors.New("shard is required")
	}
	return h.node.Join(orgSlug, shard)
}

// GetShard handles the GetShard RPC.
func (h *Handler) GetShard(_ context.Context, orgSlug string) ([]byte, error) {
	if orgSlug == "" {
		return nil, errors.New("org_slug is required")
	}
	return h.node.Shards.GetShard(orgSlug)
}

// PutSecret handles the PutSecret RPC.
func (h *Handler) PutSecret(_ context.Context, orgSlug, key string, encryptedBlob []byte) error {
	if orgSlug == "" {
		return errors.New("org_slug is required")
	}
	if key == "" {
		return errors.New("key is required")
	}
	return h.node.Store.PutSecret(orgSlug, key, encryptedBlob)
}

// GetSecret handles the GetSecret RPC.
func (h *Handler) GetSecret(_ context.Context, orgSlug, key string) ([]byte, error) {
	if orgSlug == "" {
		return nil, errors.New("org_slug is required")
	}
	if key == "" {
		return nil, errors.New("key is required")
	}
	blob, err := h.node.Store.GetSecret(orgSlug, key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errors.New("secret not found")
		}
		return nil, err
	}
	return blob, nil
}

// ListSecrets handles the ListSecrets RPC.
func (h *Handler) ListSecrets(_ context.Context, orgSlug string) ([]string, error) {
	if orgSlug == "" {
		return nil, errors.New("org_slug is required")
	}
	return h.node.Store.ListSecrets(orgSlug)
}

// SyncCRDT handles the SyncCRDT RPC.
func (h *Handler) SyncCRDT(_ context.Context, orgSlug string, since uint64) ([][]byte, error) {
	if orgSlug == "" {
		return nil, errors.New("org_slug is required")
	}
	return h.node.Store.GetCRDTOps(orgSlug, since)
}

// Status handles the Status RPC.
func (h *Handler) Status(_ context.Context) (nodeID string, threshold, totalNodes int, peers []string, ready bool) {
	return h.node.ID, h.node.Config.Threshold, h.node.Config.TotalNodes, h.node.Peers, true
}
