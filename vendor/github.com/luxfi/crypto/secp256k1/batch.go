// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1

// BatchThreshold is the minimum batch length at which BatchVerifySignature
// will try to dispatch through github.com/luxfi/accel.
var BatchThreshold = 64

// BatchVerifySignature verifies a slice of (pubkey, msgHash, sig) triples.
// pubkeys may be either 33-byte compressed or 65-byte uncompressed; all
// elements of pubkeys must use the same encoding. msgHashes must be 32
// bytes each; signatures must be 64 bytes ([R || S]).
//
// Returns one boolean per input. The result is byte-identical to repeated
// calls to VerifySignature.
func BatchVerifySignature(pubkeys [][]byte, msgHashes [][]byte, sigs [][]byte) []bool {
	n := len(pubkeys)
	if n != len(msgHashes) || n != len(sigs) {
		panic("secp256k1.BatchVerifySignature: length mismatch")
	}
	out := make([]bool, n)
	if n == 0 {
		return out
	}
	if n >= BatchThreshold {
		if ok, err := batchVerifyGPU(pubkeys, msgHashes, sigs, out); ok && err == nil {
			return out
		}
	}
	for i := range pubkeys {
		out[i] = VerifySignature(pubkeys[i], msgHashes[i], sigs[i])
	}
	return out
}
