// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mdns

import (
	"fmt"
	"time"
)

// Peer represents a discovered node on the network.
type Peer struct {
	NodeID   string            // Unique node identifier
	Addr     string            // IP address
	Port     int               // Service port
	Metadata map[string]string // Additional metadata from TXT records
	LastSeen time.Time         // Last time this peer was seen
}

// Address returns the full address string (host:port).
func (p *Peer) Address() string {
	return fmt.Sprintf("%s:%d", p.Addr, p.Port)
}

// Get returns a metadata value, or empty string if not found.
func (p *Peer) Get(key string) string {
	if p.Metadata == nil {
		return ""
	}
	return p.Metadata[key]
}

// Clone returns a deep copy of the peer.
func (p *Peer) Clone() *Peer {
	metadata := make(map[string]string, len(p.Metadata))
	for k, v := range p.Metadata {
		metadata[k] = v
	}
	return &Peer{
		NodeID:   p.NodeID,
		Addr:     p.Addr,
		Port:     p.Port,
		Metadata: metadata,
		LastSeen: p.LastSeen,
	}
}

// Age returns how long since this peer was last seen.
func (p *Peer) Age() time.Duration {
	return time.Since(p.LastSeen)
}
