//go:build grpc

// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package node

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"
)

type grpcTransport struct {
	srv *grpc.Server
}

func (t *grpcTransport) stop() {
	if t.srv != nil {
		t.srv.GracefulStop()
	}
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

	srv := grpc.NewServer()
	n.transport = &grpcTransport{srv: srv}
	n.running = true
	n.mu.Unlock()

	n.logger.Info("serving", "addr", n.Config.ListenAddr)

	// Run server in a goroutine so we can handle context cancellation.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		n.logger.Info("shutting down gRPC server")
		srv.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

// GRPCServer returns the underlying gRPC server for service registration.
func (n *Node) GRPCServer() *grpc.Server {
	if t, ok := n.transport.(*grpcTransport); ok {
		return t.srv
	}
	return nil
}
