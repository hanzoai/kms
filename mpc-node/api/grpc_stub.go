//go:build !grpc

// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package api

import "github.com/hanzoai/kms/mpc-node/node"

// RegisterServices is a no-op when built without the grpc tag.
// Rebuild with -tags grpc to register gRPC services on the node.
func RegisterServices(n *node.Node) {}
