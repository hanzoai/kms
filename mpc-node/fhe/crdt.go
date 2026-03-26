// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package fhe

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luxfi/fhe"

	"github.com/hanzoai/kms/mpc-node/store"
)

// CRDTSync implements FHE-encrypted LWW-Register CRDT synchronization between MPC nodes.
// All timestamps and values are encrypted; merge operations use homomorphic comparison
// to determine ordering without decryption.
type CRDTSync struct {
	evaluator *Evaluator
	store     *store.Store
	bitsVal   int // bit width for values
	bitsTS    int // bit width for timestamps
}

// CRDTOp represents a serialized CRDT operation (encrypted LWW-Register entry).
type CRDTOp struct {
	OrgSlug string `json:"org"`
	Key     string `json:"key"`
	// Serialized encrypted value and timestamp ciphertexts.
	EncValue     [][]byte `json:"enc_value"`
	EncTimestamp [][]byte `json:"enc_timestamp"`
}

// NewCRDTSync creates a CRDT sync engine with specified bit widths.
func NewCRDTSync(s *store.Store, eval *Evaluator, bitsVal, bitsTS int) (*CRDTSync, error) {
	if bitsVal < 1 || bitsVal > 64 {
		return nil, fmt.Errorf("fhe: bitsVal must be 1..64, got %d", bitsVal)
	}
	if bitsTS < 1 || bitsTS > 64 {
		return nil, fmt.Errorf("fhe: bitsTS must be 1..64, got %d", bitsTS)
	}
	return &CRDTSync{
		evaluator: eval,
		store:     s,
		bitsVal:   bitsVal,
		bitsTS:    bitsTS,
	}, nil
}

// CreateOp creates a CRDT operation from encrypted value and timestamp ciphertexts.
// The ciphertexts are serialized for storage and transport.
func (c *CRDTSync) CreateOp(orgSlug, key string, encValue, encTimestamp []*fhe.Ciphertext) ([]byte, error) {
	if len(encValue) != c.bitsVal {
		return nil, fmt.Errorf("fhe: value bit width %d != expected %d", len(encValue), c.bitsVal)
	}
	if len(encTimestamp) != c.bitsTS {
		return nil, fmt.Errorf("fhe: timestamp bit width %d != expected %d", len(encTimestamp), c.bitsTS)
	}

	op := CRDTOp{
		OrgSlug:      orgSlug,
		Key:          key,
		EncValue:     serializeCiphertexts(encValue),
		EncTimestamp: serializeCiphertexts(encTimestamp),
	}
	return json.Marshal(op)
}

// ParseOp deserializes a CRDT operation.
func (c *CRDTSync) ParseOp(data []byte) (*CRDTOp, error) {
	var op CRDTOp
	if err := json.Unmarshal(data, &op); err != nil {
		return nil, fmt.Errorf("fhe: parse crdt op: %w", err)
	}
	return &op, nil
}

// Merge performs LWW-Register merge on two encrypted CRDT ops.
// The result contains the value with the later timestamp, determined
// homomorphically without decryption.
func (c *CRDTSync) Merge(op1Data, op2Data []byte, params fhe.Parameters) ([]byte, error) {
	var op1, op2 CRDTOp
	if err := json.Unmarshal(op1Data, &op1); err != nil {
		return nil, fmt.Errorf("fhe: parse op1: %w", err)
	}
	if err := json.Unmarshal(op2Data, &op2); err != nil {
		return nil, fmt.Errorf("fhe: parse op2: %w", err)
	}

	if op1.OrgSlug != op2.OrgSlug || op1.Key != op2.Key {
		return nil, errors.New("fhe: cannot merge ops for different org/key")
	}

	// Deserialize ciphertexts.
	ts1, err := deserializeCiphertexts(op1.EncTimestamp, params)
	if err != nil {
		return nil, fmt.Errorf("fhe: deserialize ts1: %w", err)
	}
	ts2, err := deserializeCiphertexts(op2.EncTimestamp, params)
	if err != nil {
		return nil, fmt.Errorf("fhe: deserialize ts2: %w", err)
	}
	val1, err := deserializeCiphertexts(op1.EncValue, params)
	if err != nil {
		return nil, fmt.Errorf("fhe: deserialize val1: %w", err)
	}
	val2, err := deserializeCiphertexts(op2.EncValue, params)
	if err != nil {
		return nil, fmt.Errorf("fhe: deserialize val2: %w", err)
	}

	// Compare timestamps: is op2 > op1?
	op2Newer, err := c.evaluator.CompareGreaterThan(ts2, ts1)
	if err != nil {
		return nil, fmt.Errorf("fhe: compare timestamps: %w", err)
	}

	// Select winning value and timestamp.
	mergedVal, err := c.evaluator.MuxSelect(op2Newer, val2, val1)
	if err != nil {
		return nil, fmt.Errorf("fhe: mux value: %w", err)
	}
	mergedTS, err := c.evaluator.MuxSelect(op2Newer, ts2, ts1)
	if err != nil {
		return nil, fmt.Errorf("fhe: mux timestamp: %w", err)
	}

	return c.CreateOp(op1.OrgSlug, op1.Key, mergedVal, mergedTS)
}

// StoreOp persists a CRDT op in the local store.
func (c *CRDTSync) StoreOp(orgSlug string, opData []byte) error {
	return c.store.PutCRDTOp(orgSlug, opData)
}

// SyncWithPeer retrieves CRDT ops from a peer and merges them locally.
// This is a placeholder — actual implementation uses gRPC.
func (c *CRDTSync) SyncWithPeer(peerAddr string, orgSlug string) error {
	// Phase 1 skeleton: actual gRPC sync implemented in api/handlers.go
	return fmt.Errorf("fhe: sync not yet implemented for peer %s", peerAddr)
}

// serializeCiphertexts converts FHE ciphertexts to byte slices for storage.
func serializeCiphertexts(cts []*fhe.Ciphertext) [][]byte {
	result := make([][]byte, len(cts))
	for i, ct := range cts {
		data, err := ct.MarshalBinary()
		if err != nil {
			// Ciphertext serialization should not fail for valid ciphertexts.
			panic(fmt.Sprintf("fhe: marshal ciphertext %d: %v", i, err))
		}
		result[i] = data
	}
	return result
}

// deserializeCiphertexts converts byte slices back to FHE ciphertexts.
func deserializeCiphertexts(data [][]byte, _ fhe.Parameters) ([]*fhe.Ciphertext, error) {
	cts := make([]*fhe.Ciphertext, len(data))
	for i, d := range data {
		ct := &fhe.Ciphertext{}
		if err := ct.UnmarshalBinary(d); err != nil {
			return nil, fmt.Errorf("fhe: unmarshal ciphertext %d: %w", i, err)
		}
		cts[i] = ct
	}
	return cts, nil
}
