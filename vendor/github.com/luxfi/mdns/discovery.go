// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mdns provides zero-configuration peer discovery for local networks.
// It uses mDNS/DNS-SD (Bonjour/Avahi) for automatic service advertisement
// and peer discovery without requiring manual configuration.
package mdns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

const (
	// DefaultDomain is the mDNS domain
	DefaultDomain = "local."
	// DefaultBrowseInterval is how often to scan for peers
	DefaultBrowseInterval = 5 * time.Second
	// DefaultBrowseTimeout is the timeout for each browse operation
	DefaultBrowseTimeout = 3 * time.Second
	// DefaultStaleTimeout is when peers are considered gone
	DefaultStaleTimeout = 30 * time.Second
)

// Discovery handles mDNS-based peer discovery for zero-config clustering.
type Discovery struct {
	// Configuration
	serviceType string
	nodeID      string
	port        int
	metadata    map[string]string
	logger      *slog.Logger

	// Timing configuration
	browseInterval time.Duration
	browseTimeout  time.Duration
	staleTimeout   time.Duration

	// mDNS components
	server   *zeroconf.Server
	resolver *zeroconf.Resolver

	// Peer management
	mu      sync.RWMutex
	peers   map[string]*Peer
	handler PeerHandler

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// PeerHandler is called when peers join or leave the network.
type PeerHandler func(peer *Peer, joined bool)

// Option configures the Discovery instance.
type Option func(*Discovery)

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(d *Discovery) {
		d.logger = logger
	}
}

// WithBrowseInterval sets how often to scan for peers.
func WithBrowseInterval(interval time.Duration) Option {
	return func(d *Discovery) {
		d.browseInterval = interval
	}
}

// WithBrowseTimeout sets the timeout for each browse operation.
func WithBrowseTimeout(timeout time.Duration) Option {
	return func(d *Discovery) {
		d.browseTimeout = timeout
	}
}

// WithStaleTimeout sets when peers are considered gone.
func WithStaleTimeout(timeout time.Duration) Option {
	return func(d *Discovery) {
		d.staleTimeout = timeout
	}
}

// WithMetadata sets additional metadata to advertise.
func WithMetadata(metadata map[string]string) Option {
	return func(d *Discovery) {
		for k, v := range metadata {
			d.metadata[k] = v
		}
	}
}

// New creates a new mDNS discovery instance.
//
// serviceType should be in the format "_servicename._tcp" (e.g., "_fhed._tcp").
// nodeID is a unique identifier for this node.
// port is the port this service is listening on.
func New(serviceType, nodeID string, port int, opts ...Option) *Discovery {
	ctx, cancel := context.WithCancel(context.Background())

	d := &Discovery{
		serviceType:    serviceType,
		nodeID:         nodeID,
		port:           port,
		metadata:       make(map[string]string),
		logger:         slog.Default(),
		browseInterval: DefaultBrowseInterval,
		browseTimeout:  DefaultBrowseTimeout,
		staleTimeout:   DefaultStaleTimeout,
		peers:          make(map[string]*Peer),
		ctx:            ctx,
		cancel:         cancel,
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

// Start begins advertising this node and discovering peers.
func (d *Discovery) Start() error {
	// Build TXT records from metadata
	txtRecords := []string{
		fmt.Sprintf("id=%s", d.nodeID),
	}
	for k, v := range d.metadata {
		txtRecords = append(txtRecords, fmt.Sprintf("%s=%s", k, v))
	}

	// Register this node
	server, err := zeroconf.Register(
		d.nodeID,
		d.serviceType,
		DefaultDomain,
		d.port,
		txtRecords,
		nil, // All interfaces
	)
	if err != nil {
		return fmt.Errorf("failed to register mDNS service: %w", err)
	}
	d.server = server

	d.logger.Info("mDNS service registered",
		"nodeID", d.nodeID,
		"service", d.serviceType,
		"port", d.port,
	)

	// Create resolver for discovery
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		d.server.Shutdown()
		return fmt.Errorf("failed to create resolver: %w", err)
	}
	d.resolver = resolver

	// Start discovery loop
	d.wg.Add(1)
	go d.discoveryLoop()

	return nil
}

// Stop stops advertising and discovering.
func (d *Discovery) Stop() {
	d.cancel()
	if d.server != nil {
		d.server.Shutdown()
	}
	d.wg.Wait()

	d.logger.Info("mDNS discovery stopped", "nodeID", d.nodeID)
}

// OnPeer sets the handler for peer events.
func (d *Discovery) OnPeer(handler PeerHandler) {
	d.mu.Lock()
	d.handler = handler
	d.mu.Unlock()
}

// Peers returns all currently known peers.
func (d *Discovery) Peers() []*Peer {
	d.mu.RLock()
	defer d.mu.RUnlock()

	peers := make([]*Peer, 0, len(d.peers))
	for _, p := range d.peers {
		peers = append(peers, p.Clone())
	}
	return peers
}

// Peer returns a specific peer by ID, or nil if not found.
func (d *Discovery) Peer(nodeID string) *Peer {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if p, ok := d.peers[nodeID]; ok {
		return p.Clone()
	}
	return nil
}

// PeerCount returns the number of known peers.
func (d *Discovery) PeerCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.peers)
}

// NodeID returns this node's ID.
func (d *Discovery) NodeID() string {
	return d.nodeID
}

// ServiceType returns the service type being advertised.
func (d *Discovery) ServiceType() string {
	return d.serviceType
}

func (d *Discovery) discoveryLoop() {
	defer d.wg.Done()

	ticker := time.NewTicker(d.browseInterval)
	defer ticker.Stop()

	// Initial discovery
	d.browse()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.browse()
			d.pruneStale()
		}
	}
}

func (d *Discovery) browse() {
	entries := make(chan *zeroconf.ServiceEntry)

	go func() {
		for entry := range entries {
			d.handleEntry(entry)
		}
	}()

	ctx, cancel := context.WithTimeout(d.ctx, d.browseTimeout)
	defer cancel()

	if err := d.resolver.Browse(ctx, d.serviceType, DefaultDomain, entries); err != nil {
		if d.ctx.Err() == nil {
			d.logger.Warn("mDNS browse failed", "error", err)
		}
	}
}

func (d *Discovery) handleEntry(entry *zeroconf.ServiceEntry) {
	// Parse TXT records
	metadata := make(map[string]string)
	var nodeID string

	for _, txt := range entry.Text {
		for i := 0; i < len(txt); i++ {
			if txt[i] == '=' {
				key := txt[:i]
				value := txt[i+1:]
				metadata[key] = value
				if key == "id" {
					nodeID = value
				}
				break
			}
		}
	}

	if nodeID == "" {
		nodeID = entry.Instance
	}

	// Skip self
	if nodeID == d.nodeID {
		return
	}

	// Get first usable address
	addr := d.getAddress(entry)
	if addr == "" {
		return
	}

	peer := &Peer{
		NodeID:   nodeID,
		Addr:     addr,
		Port:     entry.Port,
		Metadata: metadata,
		LastSeen: time.Now(),
	}

	d.mu.Lock()
	existing, exists := d.peers[nodeID]
	if exists {
		existing.LastSeen = time.Now()
		existing.Addr = addr
		existing.Port = entry.Port
		existing.Metadata = metadata
		d.mu.Unlock()
		return
	}
	d.peers[nodeID] = peer
	handler := d.handler
	d.mu.Unlock()

	d.logger.Info("Peer discovered",
		"nodeID", nodeID,
		"addr", fmt.Sprintf("%s:%d", addr, entry.Port),
	)

	if handler != nil {
		handler(peer.Clone(), true)
	}
}

func (d *Discovery) getAddress(entry *zeroconf.ServiceEntry) string {
	// Prefer IPv4
	for _, ip := range entry.AddrIPv4 {
		if ip.IsLoopback() {
			continue
		}
		return ip.String()
	}
	// Fall back to IPv6
	for _, ip := range entry.AddrIPv6 {
		if ip.IsLoopback() {
			continue
		}
		return ip.String()
	}
	return ""
}

func (d *Discovery) pruneStale() {
	now := time.Now()

	d.mu.Lock()
	var stale []*Peer
	for id, peer := range d.peers {
		if now.Sub(peer.LastSeen) > d.staleTimeout {
			stale = append(stale, peer.Clone())
			delete(d.peers, id)
		}
	}
	handler := d.handler
	d.mu.Unlock()

	for _, peer := range stale {
		d.logger.Info("Peer lost", "nodeID", peer.NodeID)
		if handler != nil {
			handler(peer, false)
		}
	}
}

// LocalIPs returns the local IP addresses of this machine.
func LocalIPs() []net.IP {
	var ips []net.IP

	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ips = append(ips, ip4)
				}
			}
		}
	}
	return ips
}
