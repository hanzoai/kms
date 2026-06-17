// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

func batchVerifyGPU(pks []*PublicKey, msgs [][]byte, sigs []*Signature, out []bool) (bool, error) {
	if backend.Resolve(gpuhost.Available(), false) != backend.GPU {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	n := len(pks)
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
	pFlat := make([]uint8, n*PublicKeyLen)
	for i, p := range pks {
		b := PublicKeyToCompressedBytes(p)
		if len(b) != PublicKeyLen {
			return false, nil
		}
		copy(pFlat[i*PublicKeyLen:(i+1)*PublicKeyLen], b)
	}
	sFlat := make([]uint8, n*SignatureLen)
	for i, s := range sigs {
		b := SignatureToBytes(s)
		if len(b) != SignatureLen {
			return false, nil
		}
		copy(sFlat[i*SignatureLen:(i+1)*SignatureLen], b)
	}

	mT, err := accel.NewTensorWithData[uint8](sess, []int{n, width}, mFlat)
	if err != nil {
		return false, nil
	}
	defer mT.Close()
	sT, err := accel.NewTensorWithData[uint8](sess, []int{n, SignatureLen}, sFlat)
	if err != nil {
		return false, nil
	}
	defer sT.Close()
	pT, err := accel.NewTensorWithData[uint8](sess, []int{n, PublicKeyLen}, pFlat)
	if err != nil {
		return false, nil
	}
	defer pT.Close()
	rT, err := accel.NewTensor[uint8](sess, []int{n})
	if err != nil {
		return false, nil
	}
	defer rT.Close()

	if err := sess.Crypto().BLSVerifyBatch(mT.Untyped(), sT.Untyped(), pT.Untyped(), rT.Untyped()); err != nil {
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
