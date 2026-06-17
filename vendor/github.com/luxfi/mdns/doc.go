// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

/*
Package mdns provides zero-configuration peer discovery for local networks
using mDNS/DNS-SD (Multicast DNS Service Discovery).

This enables automatic service advertisement and peer discovery without
requiring manual configuration, DHCP, or central registries. Nodes on the
same local network can find each other automatically.

# Quick Start

	import "github.com/luxfi/mdns"

	// Create discovery for your service
	disc := mdns.New("_myservice._tcp", "node-1", 8080,
		mdns.WithMetadata(map[string]string{
			"version": "1.0.0",
			"role":    "worker",
		}),
	)

	// Handle peer events
	disc.OnPeer(func(peer *mdns.Peer, joined bool) {
		if joined {
			fmt.Printf("Peer joined: %s at %s\n", peer.NodeID, peer.Address())
		} else {
			fmt.Printf("Peer left: %s\n", peer.NodeID)
		}
	})

	// Start discovery
	if err := disc.Start(); err != nil {
		log.Fatal(err)
	}
	defer disc.Stop()

	// List all peers
	for _, peer := range disc.Peers() {
		fmt.Printf("Found: %s (%s)\n", peer.NodeID, peer.Get("version"))
	}

# Service Types

Service types follow the DNS-SD naming convention:

	_servicename._tcp  (for TCP services)
	_servicename._udp  (for UDP services)

Examples:
  - _fhed._tcp    - FHE daemon
  - _mpcd._tcp    - MPC daemon
  - _luxd._tcp    - Lux node
  - _http._tcp    - HTTP server

# How It Works

1. When Start() is called, the node registers itself via mDNS
2. A background goroutine periodically browses for other nodes
3. When new nodes are discovered, the OnPeer handler is called
4. When nodes go stale (not seen for 30s), they're removed

# Use Cases

  - Zero-config FHE/MPC clusters
  - Lux node discovery for local testnets
  - Local development environments
  - IoT device discovery
  - Microservice discovery in local networks
  - Testing distributed systems locally

# Limitations

  - Only works on local networks (mDNS is link-local)
  - Requires multicast support on the network
  - Not suitable for cross-network discovery (use Consul, etcd, etc.)
*/
package mdns
