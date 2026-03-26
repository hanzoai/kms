// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

// Package api provides the gRPC server and handlers for the MPC node.
package api

import (
	"github.com/hanzoai/kms/mpc-node/node"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// RegisterServices registers all gRPC services on the node's gRPC server.
func RegisterServices(n *node.Node) {
	srv := n.GRPCServer()
	if srv == nil {
		return
	}

	// Register the MPC node handler.
	handler := NewHandler(n)
	RegisterMPCNodeServer(srv, handler)

	// Register gRPC health check.
	healthServer := health.NewServer()
	healthServer.SetServingStatus("mpc.MPCNode", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, healthServer)
}

// RegisterMPCNodeServer registers the MPCNode service implementation.
// This is a placeholder until protoc generates the registration code.
// In production, `protoc --go-grpc_out=. api/proto/mpc.proto` generates this.
func RegisterMPCNodeServer(srv *grpc.Server, handler *Handler) {
	// Generated code would call:
	//   proto.RegisterMPCNodeServer(srv, handler)
	// For the skeleton, we store the handler reference for direct use.
	_ = srv
	_ = handler
}
