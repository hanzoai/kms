// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// smoke-zap is a one-shot KMS ZAP smoke test. It derives a service
// identity from MNEMONIC, dials the configured KMS ZAP endpoint, puts a
// secret, gets it back, and prints the result. Used by the v2.5.x image
// rollouts to prove the consensus-auth chain end-to-end.
//
// Usage:
//
//	MNEMONIC="abandon abandon ... about" \
//	KMS_ADDR=zap://127.0.0.1:19653 \
//	  smoke-zap
//
// On success: prints "smoke: ok nodeID=<...>" and exits 0. Any wire
// failure exits non-zero with the error.
//
// The same MNEMONIC value must be present in the kmsd's consensus
// snapshot (both validators and operators) for the dial to succeed —
// this command proves the chain; it does not bootstrap the snapshot.

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hanzoai/kms/pkg/kmsclient"
)

func main() {
	addr := envOr("KMS_ADDR", "zap://127.0.0.1:19653")
	servicePath := envOr("KMS_SERVICE_PATH", "hanzo/smoke")
	org := envOr("KMS_ORG", "hanzo")
	env := envOr("KMS_ENV_NAME", "smoke")
	path := envOr("KMS_PATH", "smoke")
	name := envOr("KMS_NAME", "ping")
	value := envOr("KMS_VALUE", fmt.Sprintf("pong-%d", time.Now().Unix()))

	ident, err := kmsclient.IdentityFromEnv(servicePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: derive identity: %v\n", err)
		os.Exit(1)
	}
	defer ident.Wipe()

	fmt.Printf("smoke: derived nodeID=%s servicePath=%s\n", ident.NodeID.String(), servicePath)

	c, err := kmsclient.New(kmsclient.Config{
		Endpoint:        addr,
		Org:             org,
		Env:             env,
		Identity:        ident,
		TransportNodeID: "smoke-transport",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: kmsclient.New: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := c.Put(ctx, path, name, value); err != nil {
		fmt.Fprintf(os.Stderr, "smoke: Put: %v\n", err)
		os.Exit(2)
	}
	got, err := c.Get(ctx, path, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: Get: %v\n", err)
		os.Exit(3)
	}
	if got != value {
		fmt.Fprintf(os.Stderr, "smoke: round-trip mismatch: put=%q got=%q\n", value, got)
		os.Exit(4)
	}
	fmt.Printf("smoke: ok nodeID=%s round-trip=%q\n", ident.NodeID.String(), got)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
