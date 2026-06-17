// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// batchVerifyGPU is wired only for ML-DSA-65 (Dilithium3) which is the size
// accel.LatticeOps publishes batch kernels for. Other modes fall through.
func batchVerifyGPU(pubs []*PublicKey, msgs [][]byte, sigs [][]byte, out []bool) (bool, error) {
	if backend.Resolve(gpuhost.Available(), false) != backend.GPU {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	n := len(pubs)
	pkSize := MLDSA65PublicKeySize
	sigSize := MLDSA65SignatureSize

	width := 0
	for _, m := range msgs {
		if len(m) > width {
			width = len(m)
		}
	}
	if width == 0 {
		width = 1
	}

	mFlat := make([]uint8, n*width)
	for i, m := range msgs {
		copy(mFlat[i*width:(i+1)*width], m)
	}
	pFlat := make([]uint8, n*pkSize)
	for i, p := range pubs {
		if len(p.publicKey) != pkSize {
			return false, nil
		}
		copy(pFlat[i*pkSize:(i+1)*pkSize], p.publicKey)
	}
	sFlat := make([]uint8, n*sigSize)
	for i, s := range sigs {
		if len(s) != sigSize {
			return false, nil
		}
		copy(sFlat[i*sigSize:(i+1)*sigSize], s)
	}

	mT, err := accel.NewTensorWithData[uint8](sess, []int{n, width}, mFlat)
	if err != nil {
		return false, nil
	}
	defer mT.Close()
	sT, err := accel.NewTensorWithData[uint8](sess, []int{n, sigSize}, sFlat)
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

	if err := sess.Lattice().DilithiumVerifyBatch(mT.Untyped(), sT.Untyped(), pT.Untyped(), rT.Untyped()); err != nil {
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
