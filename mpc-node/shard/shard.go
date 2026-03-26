// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

// Package shard implements Shamir threshold secret sharing for MPC node key management.
// It uses luxfi/crypto's MPC primitives for polynomial-based secret splitting.
package shard

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/hanzoai/kms/mpc-node/store"
)

var (
	ErrInvalidThreshold = errors.New("shard: threshold must be >= 2 and < totalNodes")
	ErrNotEnoughShards  = errors.New("shard: not enough shards for reconstruction")
	ErrInvalidShard     = errors.New("shard: invalid shard data")

	// fieldOrder is the order of the finite field GF(p) for Shamir splitting.
	// Using secp256k1 curve order as it's well-tested for 256-bit secrets.
	fieldOrder, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
)

// ShardManager manages Shamir threshold shards for a specific MPC node.
type ShardManager struct {
	store      *store.Store
	nodeID     string
	threshold  int // t: minimum shards needed for reconstruction
	totalNodes int // n: total number of shards
}

// NewShardManager creates a new shard manager.
// threshold (t) is the minimum number of shards required for reconstruction.
// totalNodes (n) is the total number of shards to generate.
func NewShardManager(s *store.Store, nodeID string, t, n int) (*ShardManager, error) {
	if t < 2 || t >= n {
		return nil, ErrInvalidThreshold
	}
	if n < 3 {
		return nil, fmt.Errorf("shard: totalNodes must be >= 3, got %d", n)
	}
	return &ShardManager{
		store:      s,
		nodeID:     nodeID,
		threshold:  t,
		totalNodes: n,
	}, nil
}

// Shard represents a single Shamir secret share.
type Shard struct {
	Index int      // 1-indexed shard index
	Value *big.Int // the share value
}

// Bootstrap generates n Shamir shards from a master key.
// Returns the raw shard values for distribution to MPC nodes.
// The master key is the constant term of the random polynomial.
func (sm *ShardManager) Bootstrap(orgSlug string, masterKey []byte) ([]Shard, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("shard: master key is empty")
	}

	secret := new(big.Int).SetBytes(masterKey)
	if secret.Cmp(fieldOrder) >= 0 {
		return nil, errors.New("shard: master key exceeds field order")
	}

	// Generate random polynomial coefficients: a_0 = secret, a_1..a_{t-1} random.
	coeffs := make([]*big.Int, sm.threshold)
	coeffs[0] = secret
	for i := 1; i < sm.threshold; i++ {
		coeff, err := rand.Int(rand.Reader, fieldOrder)
		if err != nil {
			return nil, fmt.Errorf("shard: generate coefficient: %w", err)
		}
		coeffs[i] = coeff
	}

	// Evaluate polynomial at x=1..n to produce n shards.
	shards := make([]Shard, sm.totalNodes)
	for i := 0; i < sm.totalNodes; i++ {
		x := big.NewInt(int64(i + 1))
		shards[i] = Shard{
			Index: i + 1,
			Value: evaluatePolynomial(coeffs, x),
		}
	}

	return shards, nil
}

// StoreShard persists this node's shard in the local ZapDB.
func (sm *ShardManager) StoreShard(orgSlug string, s Shard) error {
	return sm.store.PutShard(orgSlug, s.Value.Bytes())
}

// GetShard retrieves this node's shard from local ZapDB.
func (sm *ShardManager) GetShard(orgSlug string) ([]byte, error) {
	return sm.store.GetShard(orgSlug)
}

// Reconstruct recovers the master key from t or more shards using Lagrange interpolation.
// Returns an error if fewer than t shards are provided.
func (sm *ShardManager) Reconstruct(shards []Shard) ([]byte, error) {
	if len(shards) < sm.threshold {
		return nil, ErrNotEnoughShards
	}

	// Use exactly t shards.
	subset := shards[:sm.threshold]

	secret := lagrangeInterpolateAtZero(subset)
	return secret.Bytes(), nil
}

// Threshold returns the reconstruction threshold.
func (sm *ShardManager) Threshold() int { return sm.threshold }

// TotalNodes returns the total number of nodes.
func (sm *ShardManager) TotalNodes() int { return sm.totalNodes }

// evaluatePolynomial evaluates p(x) = sum(coeffs[i] * x^i) mod fieldOrder.
func evaluatePolynomial(coeffs []*big.Int, x *big.Int) *big.Int {
	result := new(big.Int).Set(coeffs[0])
	xPower := new(big.Int).Set(x)

	for i := 1; i < len(coeffs); i++ {
		term := new(big.Int).Mul(coeffs[i], xPower)
		term.Mod(term, fieldOrder)
		result.Add(result, term)
		result.Mod(result, fieldOrder)

		xPower.Mul(xPower, x)
		xPower.Mod(xPower, fieldOrder)
	}

	return result
}

// lagrangeInterpolateAtZero recovers p(0) from t points using Lagrange interpolation.
func lagrangeInterpolateAtZero(shards []Shard) *big.Int {
	result := big.NewInt(0)

	for i := 0; i < len(shards); i++ {
		xi := big.NewInt(int64(shards[i].Index))
		yi := shards[i].Value

		// Compute Lagrange basis polynomial L_i(0).
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := 0; j < len(shards); j++ {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(shards[j].Index))

			// num *= -xj (mod p)
			negXj := new(big.Int).Neg(xj)
			negXj.Mod(negXj, fieldOrder)
			num.Mul(num, negXj)
			num.Mod(num, fieldOrder)

			// den *= (xi - xj) (mod p)
			diff := new(big.Int).Sub(xi, xj)
			diff.Mod(diff, fieldOrder)
			den.Mul(den, diff)
			den.Mod(den, fieldOrder)
		}

		// L_i(0) = num / den (mod p)
		denInv := new(big.Int).ModInverse(den, fieldOrder)
		lagrange := new(big.Int).Mul(num, denInv)
		lagrange.Mod(lagrange, fieldOrder)

		// result += yi * L_i(0)
		term := new(big.Int).Mul(yi, lagrange)
		term.Mod(term, fieldOrder)
		result.Add(result, term)
		result.Mod(result, fieldOrder)
	}

	return result
}
