// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

// BatchThreshold is the minimum batch length at which BatchVerify will try
// to dispatch through github.com/luxfi/accel. Below this threshold the
// scalar Verify path is faster (PCIe round-trip dominates).
var BatchThreshold = 64

// BatchVerify verifies a slice of (pub, msg, sig) triples. The result slice
// has one boolean per input. When the batch is large enough and a GPU
// backend is available the verification runs on the GPU; otherwise it
// runs serially on the CPU using Verify.
//
// BatchVerify never returns an error: the GPU path silently falls back to
// CPU on any failure. Errors from individual signatures are reported as
// false in out[i].
func BatchVerify(pks []*PublicKey, msgs [][]byte, sigs []*Signature) []bool {
	n := len(pks)
	if n != len(msgs) || n != len(sigs) {
		panic("bls.BatchVerify: pks/msgs/sigs length mismatch")
	}
	out := make([]bool, n)
	if n == 0 {
		return out
	}
	if n >= BatchThreshold {
		if ok, err := batchVerifyGPU(pks, msgs, sigs, out); ok && err == nil {
			return out
		}
	}
	for i := range pks {
		out[i] = Verify(pks[i], sigs[i], msgs[i])
	}
	return out
}
