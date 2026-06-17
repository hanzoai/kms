# mdns

Zero-configuration peer discovery for local networks using mDNS/DNS-SD.

```go
import "github.com/luxfi/mdns"
```

## Quick Start

```go
// Create discovery for your service
disc := mdns.New("_myservice._tcp", "node-1", 8080,
    mdns.WithMetadata(map[string]string{
        "version": "1.0.0",
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
    fmt.Printf("Found: %s\n", peer.NodeID)
}
```

## Service Types

| Service | Type |
|---------|------|
| FHE daemon | `_fhed._tcp` |
| MPC daemon | `_mpcd._tcp` |
| Lux node | `_luxd._tcp` |

## Options

```go
mdns.New(serviceType, nodeID, port,
    mdns.WithLogger(logger),           // Custom slog logger
    mdns.WithMetadata(map[string]string{}), // TXT record metadata
    mdns.WithBrowseInterval(5*time.Second), // How often to scan
    mdns.WithBrowseTimeout(3*time.Second),  // Scan timeout
    mdns.WithStaleTimeout(30*time.Second),  // When peers are lost
)
```

## API

```go
// Lifecycle
disc.Start() error
disc.Stop()

// Events
disc.OnPeer(func(peer *Peer, joined bool))

// Query
disc.Peers() []*Peer
disc.Peer(nodeID string) *Peer
disc.PeerCount() int
disc.NodeID() string
disc.ServiceType() string

// Peer
peer.Address() string      // "192.168.1.1:8080"
peer.Get("key") string     // Metadata lookup
peer.Age() time.Duration   // Since last seen
peer.Clone() *Peer
```

## License

Copyright (C) 2025, Lux Industries Inc. All rights reserved.
