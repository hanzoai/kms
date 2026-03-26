// Copyright (C) 2020-2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package kms provides a client SDK for the Hanzo ZK-KMS system.
//
// The SDK implements zero-knowledge secret management: all encryption and
// decryption happens client-side using a Customer Encryption Key (CEK) derived
// from an admin passphrase. The CEK never leaves the client. Encrypted blobs
// are stored on distributed MPC nodes.
//
// Key hierarchy:
//
//	Passphrase -> Argon2id -> Master Key -> HKDF -> CEK (AES-256-GCM)
//
// See ZK-FHE-ARCHITECTURE.md for the full specification.
package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Client connects to a ZK-KMS MPC node cluster and provides zero-knowledge
// secret management. All secret data is encrypted client-side with the CEK;
// the MPC nodes only store encrypted blobs.
type Client struct {
	mu        sync.RWMutex
	nodes     []string // MPC node addresses (scheme://host:port)
	threshold int      // t-of-n threshold
	orgSlug   string
	cek       []byte // CEK — client-side only, never transmitted
	http      *http.Client
}

// Config configures a new ZK-KMS client.
type Config struct {
	// Nodes is the list of MPC node addresses.
	// Example: ["https://kms-mpc-0:9651", "https://kms-mpc-1:9651", "https://kms-mpc-2:9651"]
	Nodes []string

	// OrgSlug is the organization identifier.
	OrgSlug string

	// Threshold is the minimum number of nodes required for operations (t-of-n).
	Threshold int

	// HTTPClient is an optional custom HTTP client. If nil, a default client
	// with 30-second timeout is used.
	HTTPClient *http.Client

	// Compliance configures regulatory compliance mode for this org.
	// nil = standard ZK mode (no compliance features).
	Compliance *ComplianceConfig
}

// NodeStatus represents the health status of an MPC node.
type NodeStatus struct {
	Address string `json:"address"`
	Healthy bool   `json:"healthy"`
	Latency int64  `json:"latency_ms"`
	Error   string `json:"error,omitempty"`
}

// NewClient creates a new ZK-KMS client. The client is initially locked;
// call Unlock or Bootstrap before performing secret operations.
func NewClient(cfg Config) (*Client, error) {
	if len(cfg.Nodes) == 0 {
		return nil, errors.New("kms: at least one node address is required")
	}
	if cfg.OrgSlug == "" {
		return nil, errors.New("kms: org slug is required")
	}
	if cfg.Threshold < 1 {
		return nil, errors.New("kms: threshold must be at least 1")
	}
	if cfg.Threshold > len(cfg.Nodes) {
		return nil, fmt.Errorf("kms: threshold %d exceeds node count %d", cfg.Threshold, len(cfg.Nodes))
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return &Client{
		nodes:     cfg.Nodes,
		threshold: cfg.Threshold,
		orgSlug:   cfg.OrgSlug,
		http:      httpClient,
	}, nil
}

// Bootstrap creates a new org with the given passphrase. It derives the master
// key, CEK, and sends a verification hash to the MPC nodes. The passphrase
// is used locally only — it is never transmitted.
func (c *Client) Bootstrap(passphrase string) error {
	masterKey, err := DeriveMasterKey(passphrase, c.orgSlug)
	if err != nil {
		return fmt.Errorf("kms: bootstrap: %w", err)
	}
	defer clear(masterKey)

	cek, err := DeriveCEK(masterKey, c.orgSlug)
	if err != nil {
		return fmt.Errorf("kms: bootstrap: %w", err)
	}

	// Compute verification hash so recovery can confirm correctness.
	verifyHash := sha256.Sum256(masterKey)

	body := bootstrapRequest{
		OrgSlug:                  c.orgSlug,
		Threshold:                c.threshold,
		NodeCount:                len(c.nodes),
		RecoveryVerificationHash: verifyHash[:],
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("kms: bootstrap: marshal: %w", err)
	}

	// Send bootstrap to all nodes.
	if err := c.broadcastPost("/v1/zk/init", data); err != nil {
		return fmt.Errorf("kms: bootstrap: %w", err)
	}

	c.mu.Lock()
	c.cek = cek
	c.mu.Unlock()

	return nil
}

// Unlock derives the CEK from the passphrase (client-side only) and stores
// it in memory. The passphrase is never transmitted.
func (c *Client) Unlock(passphrase string) error {
	masterKey, err := DeriveMasterKey(passphrase, c.orgSlug)
	if err != nil {
		return fmt.Errorf("kms: unlock: %w", err)
	}
	defer clear(masterKey)

	cek, err := DeriveCEK(masterKey, c.orgSlug)
	if err != nil {
		return fmt.Errorf("kms: unlock: %w", err)
	}

	c.mu.Lock()
	c.cek = cek
	c.mu.Unlock()

	return nil
}

// Lock zeros the CEK from memory.
func (c *Client) Lock() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cek != nil {
		clear(c.cek)
		c.cek = nil
	}
}

// IsUnlocked reports whether the client has a CEK in memory.
func (c *Client) IsUnlocked() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cek != nil
}

// ExportCEK returns a copy of the CEK for client-side encryption operations.
// The caller is responsible for zeroing the returned key when done.
// Returns an error if the client is locked.
func (c *Client) ExportCEK() ([]byte, error) {
	return c.getCEK()
}

// SealAESGCM encrypts plaintext with AES-256-GCM using the provided key.
// Returns nonce || ciphertext || tag.
func SealAESGCM(key, plaintext, aad []byte) ([]byte, error) {
	return sealAESGCM(key, plaintext, aad)
}

// OpenAESGCM decrypts an AES-256-GCM ciphertext with the provided key.
// Expects nonce || ciphertext || tag as input.
func OpenAESGCM(key, data, aad []byte) ([]byte, error) {
	return openAESGCM(key, data, aad)
}

// getCEK returns a copy of the CEK or an error if the client is locked.
func (c *Client) getCEK() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.cek == nil {
		return nil, errors.New("kms: client is locked — call Unlock first")
	}

	cekCopy := make([]byte, len(c.cek))
	copy(cekCopy, c.cek)
	return cekCopy, nil
}

// Status returns the health status of all configured MPC nodes.
func (c *Client) Status() ([]NodeStatus, error) {
	statuses := make([]NodeStatus, len(c.nodes))

	for i, node := range c.nodes {
		status := NodeStatus{Address: node}
		start := time.Now()

		resp, err := c.http.Get(node + "/v1/zk/health")
		if err != nil {
			status.Error = err.Error()
			statuses[i] = status
			continue
		}
		resp.Body.Close()

		status.Latency = time.Since(start).Milliseconds()
		status.Healthy = resp.StatusCode == http.StatusOK
		if resp.StatusCode != http.StatusOK {
			status.Error = fmt.Sprintf("unexpected status: %d", resp.StatusCode)
		}
		statuses[i] = status
	}

	return statuses, nil
}

// broadcastPost sends a POST request to all configured nodes. Returns an error
// if fewer than threshold nodes respond successfully.
func (c *Client) broadcastPost(path string, body []byte) error {
	type result struct {
		node string
		err  error
	}

	ch := make(chan result, len(c.nodes))

	for _, node := range c.nodes {
		go func(addr string) {
			err := c.postJSON(addr+path, body)
			ch <- result{node: addr, err: err}
		}(node)
	}

	var successes int
	var lastErr error
	for range c.nodes {
		r := <-ch
		if r.err != nil {
			lastErr = fmt.Errorf("node %s: %w", r.node, r.err)
		} else {
			successes++
		}
	}

	if successes < c.threshold {
		return fmt.Errorf("only %d of %d nodes responded (need %d): %w",
			successes, len(c.nodes), c.threshold, lastErr)
	}
	return nil
}

// quorumGet sends a GET request to nodes until threshold responses are received.
// Returns the body from the first successful response.
func (c *Client) quorumGet(path string) ([]byte, error) {
	type result struct {
		body []byte
		err  error
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan result, len(c.nodes))

	for _, node := range c.nodes {
		go func(addr string) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr+path, nil)
			if err != nil {
				ch <- result{err: err}
				return
			}
			resp, err := c.http.Do(req)
			if err != nil {
				ch <- result{err: err}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				ch <- result{err: fmt.Errorf("status %d", resp.StatusCode)}
				return
			}

			data, err := io.ReadAll(resp.Body)
			if err != nil {
				ch <- result{err: err}
				return
			}
			ch <- result{body: data}
		}(node)
	}

	var firstBody []byte
	var successes int
	var lastErr error

	for range c.nodes {
		r := <-ch
		if r.err != nil {
			lastErr = r.err
			continue
		}
		successes++
		if firstBody == nil {
			firstBody = r.body
		}
		if successes >= c.threshold {
			return firstBody, nil
		}
	}

	return nil, fmt.Errorf("only %d of %d nodes responded (need %d): %w",
		successes, len(c.nodes), c.threshold, lastErr)
}

// postJSON sends a POST request with JSON body to a single node.
func (c *Client) postJSON(url string, body []byte) error {
	resp, err := c.http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// deleteRequest sends a DELETE request to a single node.
func (c *Client) deleteRequest(url string) error {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// bootstrapRequest is the JSON body sent to /v1/zk/init.
type bootstrapRequest struct {
	OrgSlug                  string `json:"org_slug"`
	Threshold                int    `json:"threshold"`
	NodeCount                int    `json:"node_count"`
	RecoveryVerificationHash []byte `json:"recovery_verification_hash"`
}
