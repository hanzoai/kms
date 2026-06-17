// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

// BatchThreshold is the minimum batch length at which BatchVerify will try
// to dispatch through github.com/luxfi/accel.
var BatchThreshold = 64

// BatchVerify verifies a slice of (pub, msg, sig) triples for the same
// ML-DSA mode. The result slice has one boolean per input. When the batch
// is large enough and a GPU backend is available the verification runs on
// the GPU; otherwise it runs serially on the CPU using VerifySignature.
//
// All inputs must use the same mode; if pubs[i].mode differs from the
// first one, BatchVerify panics.
func BatchVerify(pubs []*PublicKey, msgs [][]byte, sigs [][]byte) []bool {
	n := len(pubs)
	if n != len(msgs) || n != len(sigs) {
		panic("mldsa.BatchVerify: pubs/msgs/sigs length mismatch")
	}
	out := make([]bool, n)
	if n == 0 {
		return out
	}
	mode := pubs[0].mode
	for i := 1; i < n; i++ {
		if pubs[i].mode != mode {
			panic("mldsa.BatchVerify: mixed modes not supported")
		}
	}

	if n >= BatchThreshold && mode == MLDSA65 {
		// accel exposes a Dilithium3 ≃ ML-DSA-65 batch verify kernel.
		if ok, err := batchVerifyGPU(pubs, msgs, sigs, out); ok && err == nil {
			return out
		}
	}
	for i := range pubs {
		out[i] = pubs[i].VerifySignature(msgs[i], sigs[i])
	}
	return out
}
