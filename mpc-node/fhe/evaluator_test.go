// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package fhe

import (
	"testing"

	"github.com/luxfi/fhe"
)

func setupFHE(t *testing.T) (fhe.Parameters, *fhe.Encryptor, *fhe.Decryptor, *Evaluator) {
	t.Helper()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatal(err)
	}
	keygen := fhe.NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)

	enc := fhe.NewEncryptor(params, sk)
	dec := fhe.NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	return params, enc, dec, eval
}

func encryptUint(enc *fhe.Encryptor, v uint8, nbits int) []*fhe.Ciphertext {
	cts := make([]*fhe.Ciphertext, nbits)
	for i := 0; i < nbits; i++ {
		cts[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return cts
}

func decryptUint(dec *fhe.Decryptor, cts []*fhe.Ciphertext) uint8 {
	var v uint8
	for i, ct := range cts {
		if dec.Decrypt(ct) {
			v |= 1 << i
		}
	}
	return v
}

func TestCompareGreaterThan(t *testing.T) {
	_, enc, dec, eval := setupFHE(t)

	tests := []struct {
		name string
		a, b uint8
		want bool
	}{
		{"5 > 3", 5, 3, true},
		{"3 > 5", 3, 5, false},
		{"7 > 7", 7, 7, false},
		{"0 > 0", 0, 0, false},
		{"15 > 0", 15, 0, true},
		{"0 > 15", 0, 15, false},
		{"1 > 0", 1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nbits := 4
			encA := encryptUint(enc, tt.a, nbits)
			encB := encryptUint(enc, tt.b, nbits)

			result, err := eval.CompareGreaterThan(encA, encB)
			if err != nil {
				t.Fatal(err)
			}
			got := dec.Decrypt(result)
			if got != tt.want {
				t.Fatalf("CompareGreaterThan(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMuxSelect(t *testing.T) {
	_, enc, dec, eval := setupFHE(t)

	nbits := 4
	valA := encryptUint(enc, 7, nbits)  // true branch
	valB := encryptUint(enc, 12, nbits) // false branch

	// cond = true → select valA
	condTrue := enc.Encrypt(true)
	selected, err := eval.MuxSelect(condTrue, valA, valB)
	if err != nil {
		t.Fatal(err)
	}
	got := decryptUint(dec, selected)
	if got != 7 {
		t.Fatalf("MuxSelect(true) = %d, want 7", got)
	}

	// cond = false → select valB
	condFalse := enc.Encrypt(false)
	selected, err = eval.MuxSelect(condFalse, valA, valB)
	if err != nil {
		t.Fatal(err)
	}
	got = decryptUint(dec, selected)
	if got != 12 {
		t.Fatalf("MuxSelect(false) = %d, want 12", got)
	}
}

func TestCRDTMerge(t *testing.T) {
	params, enc, dec, eval := setupFHE(t)

	bitsVal := 4
	bitsTS := 4

	// Create a dummy store for CRDT (we only test merge, not persistence).
	cs, err := NewCRDTSync(nil, eval, bitsVal, bitsTS)
	if err != nil {
		t.Fatal(err)
	}

	// Node A: value=7, timestamp=3
	valA := encryptUint(enc, 7, bitsVal)
	tsA := encryptUint(enc, 3, bitsTS)
	opA, err := cs.CreateOp("acme", "db-pass", valA, tsA)
	if err != nil {
		t.Fatal(err)
	}

	// Node B: value=12, timestamp=5 (later)
	valB := encryptUint(enc, 12, bitsVal)
	tsB := encryptUint(enc, 5, bitsTS)
	opB, err := cs.CreateOp("acme", "db-pass", valB, tsB)
	if err != nil {
		t.Fatal(err)
	}

	// Merge: should select Node B (later timestamp).
	merged, err := cs.Merge(opA, opB, params)
	if err != nil {
		t.Fatal(err)
	}

	// Parse and decrypt the merged result.
	mergedOp, err := cs.ParseOp(merged)
	if err != nil {
		t.Fatal(err)
	}

	mergedVal, err := deserializeCiphertexts(mergedOp.EncValue, params)
	if err != nil {
		t.Fatal(err)
	}
	mergedTS, err := deserializeCiphertexts(mergedOp.EncTimestamp, params)
	if err != nil {
		t.Fatal(err)
	}

	gotVal := decryptUint(dec, mergedVal)
	gotTS := decryptUint(dec, mergedTS)

	if gotVal != 12 {
		t.Fatalf("merged value = %d, want 12", gotVal)
	}
	if gotTS != 5 {
		t.Fatalf("merged timestamp = %d, want 5", gotTS)
	}
}

func TestCRDTMergeCommutative(t *testing.T) {
	params, enc, dec, eval := setupFHE(t)

	bitsVal := 4
	bitsTS := 4
	cs, _ := NewCRDTSync(nil, eval, bitsVal, bitsTS)

	valA := encryptUint(enc, 3, bitsVal)
	tsA := encryptUint(enc, 2, bitsTS)
	opA, _ := cs.CreateOp("acme", "key", valA, tsA)

	valB := encryptUint(enc, 9, bitsVal)
	tsB := encryptUint(enc, 8, bitsTS)
	opB, _ := cs.CreateOp("acme", "key", valB, tsB)

	// merge(A, B)
	m1, err := cs.Merge(opA, opB, params)
	if err != nil {
		t.Fatal(err)
	}
	// merge(B, A)
	m2, err := cs.Merge(opB, opA, params)
	if err != nil {
		t.Fatal(err)
	}

	// Both should produce value=9, ts=8.
	for label, m := range map[string][]byte{"A,B": m1, "B,A": m2} {
		parsed, _ := cs.ParseOp(m)
		v, _ := deserializeCiphertexts(parsed.EncValue, params)
		ts, _ := deserializeCiphertexts(parsed.EncTimestamp, params)
		gotV := decryptUint(dec, v)
		gotTS := decryptUint(dec, ts)
		if gotV != 9 || gotTS != 8 {
			t.Fatalf("merge(%s) = val=%d ts=%d, want val=9 ts=8", label, gotV, gotTS)
		}
	}
}
