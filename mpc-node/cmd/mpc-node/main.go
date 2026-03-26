// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

// Command mpc-node runs a single MPC node in the Hanzo KMS distributed cluster.
//
// Usage:
//
//	mpc-node bootstrap --org <slug> --threshold 2 --nodes 3 --passphrase <pass>
//	mpc-node join --org <slug> --shard-file <path>
//	mpc-node serve --addr :9651 --peers node2:9651,node3:9651
//	mpc-node sync --org <slug>
//	mpc-node status
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hanzoai/kms/mpc-node/api"
	"github.com/hanzoai/kms/mpc-node/node"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "bootstrap":
		cmdBootstrap(os.Args[2:])
	case "join":
		cmdJoin(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "sync":
		cmdSync(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: mpc-node <command> [flags]

Commands:
  bootstrap   Initialize a new org's key material
  join        Accept a shard from a bootstrap ceremony
  serve       Start the gRPC server
  sync        Trigger CRDT sync with peers
  status      Print node status

Common flags:
  --node-id     Node identifier (default: from MPC_NODE_ID env)
  --data-dir    ZapDB data directory (default: /data/kms-mpc)
  --enc-key     ZapDB encryption key (hex, from MPC_ENCRYPTION_KEY env)
  --tier        KMS tier: standard, mpc, tfhe, sovereign (default: mpc)

`)
}

func baseFlags(fs *flag.FlagSet) (nodeID, dataDir, encKeyHex, tierStr *string, threshold, totalNodes *int) {
	nodeID = fs.String("node-id", envOr("MPC_NODE_ID", "kms-mpc-0"), "node identifier")
	dataDir = fs.String("data-dir", envOr("MPC_DATA_DIR", "/data/kms-mpc"), "ZapDB data directory")
	encKeyHex = fs.String("enc-key", envOr("MPC_ENCRYPTION_KEY", ""), "ZapDB encryption key (hex)")
	tierStr = fs.String("tier", envOr("MPC_TIER", "mpc"), "KMS tier: standard, mpc, tfhe, sovereign")
	threshold = fs.Int("threshold", 2, "Shamir threshold (t)")
	totalNodes = fs.Int("nodes", 3, "total MPC nodes (n)")
	return
}

func makeConfig(nodeID, dataDir, encKeyHex, tierStr string, threshold, totalNodes int, listenAddr string, peers []string) (*node.Config, error) {
	if encKeyHex == "" {
		return nil, fmt.Errorf("encryption key is required (--enc-key or MPC_ENCRYPTION_KEY)")
	}
	encKey, err := hex.DecodeString(encKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key hex: %w", err)
	}
	tier, err := node.ParseKMSTier(tierStr)
	if err != nil {
		return nil, err
	}
	return &node.Config{
		NodeID:        nodeID,
		DataDir:       dataDir,
		EncryptionKey: encKey,
		Tier:          tier,
		Threshold:     threshold,
		TotalNodes:    totalNodes,
		ListenAddr:    listenAddr,
		Peers:         peers,
	}, nil
}

func cmdBootstrap(args []string) {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	nodeID, dataDir, encKeyHex, tierStr, threshold, totalNodes := baseFlags(fs)
	org := fs.String("org", "", "org slug (required)")
	passphrase := fs.String("passphrase", "", "admin passphrase (required)")
	nodeIndex := fs.Int("index", 1, "this node's shard index (1-based)")
	fs.Parse(args)

	if *org == "" || *passphrase == "" {
		fmt.Fprintln(os.Stderr, "error: --org and --passphrase are required")
		os.Exit(1)
	}

	cfg, err := makeConfig(*nodeID, *dataDir, *encKeyHex, *tierStr, *threshold, *totalNodes, ":9651", nil)
	if err != nil {
		fatal(err)
	}
	n, err := node.NewNode(cfg)
	if err != nil {
		fatal(err)
	}
	defer n.Shutdown()

	result, err := n.Bootstrap(*org, *passphrase, *nodeIndex)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("Bootstrap complete for org %q (tier: %s)\n", *org, *tierStr)
	fmt.Printf("  Threshold: %d-of-%d\n", *threshold, *totalNodes)
	fmt.Printf("  Recovery hash: %x\n", result.RecoveryVerification)
	fmt.Printf("  Shards generated: %d\n", len(result.Shards))
	for i, s := range result.Shards {
		fmt.Printf("  Shard %d: %x\n", i+1, s.Value.Bytes())
	}
}

func cmdJoin(args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	nodeID, dataDir, encKeyHex, tierStr, threshold, totalNodes := baseFlags(fs)
	org := fs.String("org", "", "org slug (required)")
	shardFile := fs.String("shard-file", "", "path to shard file (hex-encoded)")
	fs.Parse(args)

	if *org == "" || *shardFile == "" {
		fmt.Fprintln(os.Stderr, "error: --org and --shard-file are required")
		os.Exit(1)
	}

	shardHex, err := os.ReadFile(*shardFile)
	if err != nil {
		fatal(fmt.Errorf("read shard file: %w", err))
	}
	shardBytes, err := hex.DecodeString(strings.TrimSpace(string(shardHex)))
	if err != nil {
		fatal(fmt.Errorf("decode shard hex: %w", err))
	}

	cfg, err := makeConfig(*nodeID, *dataDir, *encKeyHex, *tierStr, *threshold, *totalNodes, ":9651", nil)
	if err != nil {
		fatal(err)
	}
	n, err := node.NewNode(cfg)
	if err != nil {
		fatal(err)
	}
	defer n.Shutdown()

	if err := n.Join(*org, shardBytes); err != nil {
		fatal(err)
	}
	fmt.Printf("Joined org %q successfully\n", *org)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	nodeID, dataDir, encKeyHex, tierStr, threshold, totalNodes := baseFlags(fs)
	addr := fs.String("addr", envOr("MPC_LISTEN_ADDR", ":9651"), "gRPC listen address")
	peersStr := fs.String("peers", envOr("MPC_PEERS", ""), "comma-separated peer addresses")
	fs.Parse(args)

	var peers []string
	if *peersStr != "" {
		peers = strings.Split(*peersStr, ",")
	}

	cfg, err := makeConfig(*nodeID, *dataDir, *encKeyHex, *tierStr, *threshold, *totalNodes, *addr, peers)
	if err != nil {
		fatal(err)
	}
	n, err := node.NewNode(cfg)
	if err != nil {
		fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Register gRPC services before serving.
	// The node creates its gRPC server in Serve(), but we need to register services first.
	// So we call Serve which will block — registration happens internally.
	go func() {
		<-ctx.Done()
		slog.Info("received shutdown signal")
	}()

	if err := n.Serve(ctx); err != nil {
		fatal(err)
	}

	api.RegisterServices(n)

	slog.Info("node stopped")
}

func cmdSync(args []string) {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	nodeID, dataDir, encKeyHex, tierStr, threshold, totalNodes := baseFlags(fs)
	org := fs.String("org", "", "org slug (required)")
	fs.Parse(args)

	if *org == "" {
		fmt.Fprintln(os.Stderr, "error: --org is required")
		os.Exit(1)
	}

	cfg, err := makeConfig(*nodeID, *dataDir, *encKeyHex, *tierStr, *threshold, *totalNodes, ":9651", nil)
	if err != nil {
		fatal(err)
	}
	n, err := node.NewNode(cfg)
	if err != nil {
		fatal(err)
	}
	defer n.Shutdown()

	if err := n.Sync(*org); err != nil {
		fmt.Fprintf(os.Stderr, "sync: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("sync complete")
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	nodeID, dataDir, encKeyHex, tierStr, threshold, totalNodes := baseFlags(fs)
	fs.Parse(args)

	cfg, err := makeConfig(*nodeID, *dataDir, *encKeyHex, *tierStr, *threshold, *totalNodes, ":9651", nil)
	if err != nil {
		fatal(err)
	}
	n, err := node.NewNode(cfg)
	if err != nil {
		fatal(err)
	}
	defer n.Shutdown()

	fmt.Printf("Node ID:     %s\n", n.ID)
	fmt.Printf("Tier:        %s\n", n.Config.Tier)
	fmt.Printf("Threshold:   %d-of-%d\n", n.Config.Threshold, n.Config.TotalNodes)
	fmt.Printf("Data dir:    %s\n", n.Config.DataDir)
	fmt.Printf("Listen addr: %s\n", n.Config.ListenAddr)
	fmt.Printf("Peers:       %v\n", n.Peers)
	fmt.Printf("FHE CRDT:    %v\n", n.Config.Tier.RequiresFHE())
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
