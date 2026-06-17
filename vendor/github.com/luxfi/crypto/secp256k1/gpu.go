// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

func batchVerifyGPU(pubkeys, msgHashes, sigs [][]byte, out []bool) (bool, error) {
	if backend.Resolve(gpuhost.Available(), false) != backend.GPU {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	n := len(pubkeys)
	if n == 0 {
		return false, nil
	}
	pkSize := len(pubkeys[0])
	if pkSize != 33 && pkSize != 65 {
		return false, nil
	}
	for _, p := range pubkeys {
		if len(p) != pkSize {
			return false, nil
		}
	}

	mFlat := make([]uint8, n*32)
	for i, m := range msgHashes {
		if len(m) != 32 {
			return false, nil
		}
		copy(mFlat[i*32:(i+1)*32], m)
	}
	sFlat := make([]uint8, n*64)
	for i, s := range sigs {
		if len(s) != 64 {
			return false, nil
		}
		copy(sFlat[i*64:(i+1)*64], s)
	}
	pFlat := make([]uint8, n*pkSize)
	for i, p := range pubkeys {
		copy(pFlat[i*pkSize:(i+1)*pkSize], p)
	}

	mT, err := accel.NewTensorWithData[uint8](sess, []int{n, 32}, mFlat)
	if err != nil {
		return false, nil
	}
	defer mT.Close()
	sT, err := accel.NewTensorWithData[uint8](sess, []int{n, 64}, sFlat)
	if err != nil {
		return false, nil
	}
	defer sT.Close()
	pT, err := accel.NewTensorWithData[uint8](sess, []int{n, pkSize}, pFlat)
	if err != nil {
		return false, nil
	}
	defer pT.Close()
	rT, err := accel.NewTensor[uint8](sess, []int{n})
	if err != nil {
		return false, nil
	}
	defer rT.Close()

	if err := sess.Crypto().ECDSAVerifyBatch(mT.Untyped(), sT.Untyped(), pT.Untyped(), rT.Untyped()); err != nil {
		return false, nil
	}
	bytes, err := rT.ToSlice()
	if err != nil {
		return false, nil
	}
	for i, b := range bytes {
		out[i] = b == 1
	}
	return true, nil
}
