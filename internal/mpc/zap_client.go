// Package mpc provides a ZAP client for communicating with the MPC daemon.
// Adapted from github.com/luxfi/kms/pkg/mpc.
package mpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/luxfi/zap"
)

// ZAP opcodes for KMS <-> MPC protocol.
const (
	OpStatus  uint16 = 0x0001
	OpKeygen  uint16 = 0x0010
	OpSign    uint16 = 0x0011
	OpReshare uint16 = 0x0012
	OpWallet  uint16 = 0x0020
)

// ClusterStatus is the response from a status call.
type ClusterStatus struct {
	NodeID         string `json:"node_id"`
	Mode           string `json:"mode"`
	ExpectedPeers  int    `json:"expected_peers"`
	ConnectedPeers int    `json:"connected_peers"`
	Ready          bool   `json:"ready"`
	Threshold      int    `json:"threshold"`
	Version        string `json:"version"`
}

// KeygenRequest is the keygen input.
type KeygenRequest struct {
	Name     string `json:"name"`
	KeyType  string `json:"key_type"`
	Protocol string `json:"protocol"`
}

// KeygenResult is the keygen output.
type KeygenResult struct {
	ID           string   `json:"id"`
	WalletID     string   `json:"walletId"`
	VaultID      string   `json:"vaultId"`
	KeyType      string   `json:"keyType"`
	Protocol     string   `json:"protocol"`
	ECDSAPubkey  *string  `json:"ecdsaPubkey"`
	EDDSAPubkey  *string  `json:"eddsaPubkey"`
	Threshold    int      `json:"threshold"`
	Participants []string `json:"participants"`
	Version      int      `json:"version"`
	Status       string   `json:"status"`
}

// SignRequest is the sign input.
type SignRequest struct {
	KeyType  string `json:"key_type"`
	WalletID string `json:"wallet_id"`
	Message  []byte `json:"message"`
}

// SignResult is the sign output.
type SignResult struct {
	R         string `json:"r,omitempty"`
	S         string `json:"s,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// ReshareRequest is the reshare input.
type ReshareRequest struct {
	NewThreshold    int      `json:"new_threshold"`
	NewParticipants []string `json:"new_participants"`
}

// ZapClient communicates with the MPC daemon over ZAP.
type ZapClient struct {
	node   *zap.Node
	peerID string
}

// NewZapClient creates a ZAP client for MPC communication.
// If mpcAddr is empty, uses mDNS discovery.
func NewZapClient(nodeID, mpcAddr string) (*ZapClient, error) {
	useMDNS := mpcAddr == ""
	if useMDNS {
		slog.Warn("mpc: mDNS discovery enabled -- unsafe outside development; set MPC_ADDR for production")
	}

	node := zap.NewNode(zap.NodeConfig{
		NodeID:      nodeID,
		ServiceType: "_hanzo-kms._tcp",
		NoDiscovery: !useMDNS,
		Logger:      slog.Default(),
	})

	c := &ZapClient{node: node}

	if !useMDNS {
		if err := node.ConnectDirect(mpcAddr); err != nil {
			return nil, fmt.Errorf("mpc: connect %s: %w", mpcAddr, err)
		}
		peers := node.Peers()
		if len(peers) > 0 {
			c.peerID = peers[0]
		}
	}

	return c, nil
}

func (c *ZapClient) call(ctx context.Context, op uint16, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	b := zap.NewBuilder(len(data) + 64)
	opBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(opBytes, op)
	b.WriteBytes(append(opBytes, data...))
	raw := b.Finish()

	msg, err := zap.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("mpc: zap build: %w", err)
	}

	resp, err := c.node.Call(ctx, c.peerID, msg)
	if err != nil {
		return nil, fmt.Errorf("mpc: zap call op=0x%04x: %w", op, err)
	}

	body := resp.Bytes()
	if len(body) < zap.HeaderSize+2 {
		return nil, fmt.Errorf("mpc: zap response too short (%d bytes) for op=0x%04x", len(body), op)
	}

	respOp := binary.LittleEndian.Uint16(body[zap.HeaderSize : zap.HeaderSize+2])
	if respOp != op {
		return nil, fmt.Errorf("mpc: zap response opcode mismatch: sent=0x%04x got=0x%04x", op, respOp)
	}

	if len(body) <= zap.HeaderSize+2 {
		return []byte("{}"), nil
	}
	return body[zap.HeaderSize+2:], nil
}

// Status returns the MPC cluster status.
func (c *ZapClient) Status(ctx context.Context) (*ClusterStatus, error) {
	data, err := c.call(ctx, OpStatus, nil)
	if err != nil {
		return nil, err
	}
	var status ClusterStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("mpc: decode status: %w", err)
	}
	return &status, nil
}

// Keygen creates a new MPC wallet.
func (c *ZapClient) Keygen(ctx context.Context, vaultID string, req KeygenRequest) (*KeygenResult, error) {
	payload := struct {
		VaultID string       `json:"vault_id"`
		Request KeygenRequest `json:"request"`
	}{vaultID, req}

	data, err := c.call(ctx, OpKeygen, payload)
	if err != nil {
		return nil, err
	}
	var result KeygenResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("mpc: decode keygen: %w", err)
	}
	return &result, nil
}

// Sign requests a threshold signature.
func (c *ZapClient) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	data, err := c.call(ctx, OpSign, req)
	if err != nil {
		return nil, err
	}
	var result SignResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("mpc: decode sign: %w", err)
	}
	return &result, nil
}

// Reshare triggers key resharing.
func (c *ZapClient) Reshare(ctx context.Context, walletID string, req ReshareRequest) error {
	payload := struct {
		WalletID string         `json:"wallet_id"`
		Request  ReshareRequest `json:"request"`
	}{walletID, req}
	_, err := c.call(ctx, OpReshare, payload)
	return err
}

// Close shuts down the ZAP node.
func (c *ZapClient) Close() {
	c.node.Stop()
}
