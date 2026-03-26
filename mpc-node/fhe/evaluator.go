// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

// Package fhe provides TFHE evaluation on encrypted metadata and
// FHE-encrypted CRDT synchronization between MPC nodes.
package fhe

import (
	"fmt"

	"github.com/luxfi/fhe"
)

// Evaluator wraps luxfi/fhe for TFHE gate evaluation on encrypted metadata.
// It is initialized from a bootstrap key and does not require the secret key.
type Evaluator struct {
	params fhe.Parameters
	eval   *fhe.Evaluator
}

// NewEvaluator creates an Evaluator from FHE parameters and a bootstrap key.
func NewEvaluator(params fhe.Parameters, bsk *fhe.BootstrapKey) *Evaluator {
	return &Evaluator{
		params: params,
		eval:   fhe.NewEvaluator(params, bsk),
	}
}

// CompareGreaterThan compares two encrypted unsigned integers (bit arrays, LSB-first).
// Returns an encrypted boolean: true if a > b.
func (e *Evaluator) CompareGreaterThan(a, b []*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("fhe: bit width mismatch: %d vs %d", len(a), len(b))
	}
	nbits := len(a)
	if nbits == 0 {
		return nil, fmt.Errorf("fhe: empty ciphertext arrays")
	}

	// MSB-first comparison: scan from MSB down.
	// aGtB starts as false, eqSoFar starts as true.
	var aGtB, eqSoFar *fhe.Ciphertext

	for i := nbits - 1; i >= 0; i-- {
		// bitGt = A[i] AND NOT(B[i])
		bitGt, err := e.eval.ANDNY(b[i], a[i])
		if err != nil {
			return nil, fmt.Errorf("fhe: bit %d ANDNY: %w", i, err)
		}
		// bitEq = XNOR(A[i], B[i])
		bitEq, err := e.eval.XNOR(a[i], b[i])
		if err != nil {
			return nil, fmt.Errorf("fhe: bit %d XNOR: %w", i, err)
		}

		if i == nbits-1 {
			aGtB = bitGt
			eqSoFar = bitEq
		} else {
			contrib, err := e.eval.AND(eqSoFar, bitGt)
			if err != nil {
				return nil, fmt.Errorf("fhe: bit %d AND: %w", i, err)
			}
			aGtB, err = e.eval.OR(aGtB, contrib)
			if err != nil {
				return nil, fmt.Errorf("fhe: bit %d OR: %w", i, err)
			}
			eqSoFar, err = e.eval.AND(eqSoFar, bitEq)
			if err != nil {
				return nil, fmt.Errorf("fhe: bit %d eq-chain: %w", i, err)
			}
		}
	}
	return aGtB, nil
}

// MuxSelect selects between two encrypted values based on an encrypted condition.
// If cond is true, returns trueVal; otherwise returns falseVal.
// Both values must have the same bit width.
func (e *Evaluator) MuxSelect(cond *fhe.Ciphertext, trueVal, falseVal []*fhe.Ciphertext) ([]*fhe.Ciphertext, error) {
	if len(trueVal) != len(falseVal) {
		return nil, fmt.Errorf("fhe: mux bit width mismatch: %d vs %d", len(trueVal), len(falseVal))
	}
	result := make([]*fhe.Ciphertext, len(trueVal))
	for i := range trueVal {
		v, err := e.eval.MUX(cond, trueVal[i], falseVal[i])
		if err != nil {
			return nil, fmt.Errorf("fhe: mux bit %d: %w", i, err)
		}
		result[i] = v
	}
	return result, nil
}

// AND evaluates encrypted AND gate.
func (e *Evaluator) AND(a, b *fhe.Ciphertext) (*fhe.Ciphertext, error) {
	return e.eval.AND(a, b)
}

// OR evaluates encrypted OR gate.
func (e *Evaluator) OR(a, b *fhe.Ciphertext) (*fhe.Ciphertext, error) {
	return e.eval.OR(a, b)
}

// NOT evaluates encrypted NOT gate.
func (e *Evaluator) NOT(a *fhe.Ciphertext) *fhe.Ciphertext {
	return e.eval.NOT(a)
}
