//go:build !grpc

// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package node

import (
	"context"
	"errors"
)

// Serve is a stub when built without the grpc tag.
// The ZAP-native server implementation is pending; rebuild with -tags grpc
// to use the gRPC server.
func (n *Node) Serve(ctx context.Context) error {
	return errors.New("node: gRPC server disabled — rebuild with -tags grpc, ZAP-native server pending")
}
