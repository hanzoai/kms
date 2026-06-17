//go:build cgo

package accel

import (
	"github.com/luxfi/accel/internal/capi"
)

// cgoTensorHandle implements tensorHandle using CGO.
type cgoTensorHandle struct {
	tensor *capi.Tensor
}

func (h *cgoTensorHandle) ndim() int {
	return h.tensor.NDim()
}

func (h *cgoTensorHandle) shape(dim int) int {
	return h.tensor.Shape(dim)
}

func (h *cgoTensorHandle) numel() int {
	return h.tensor.NumEl()
}

func (h *cgoTensorHandle) bytes() int {
	return h.tensor.Bytes()
}

func (h *cgoTensorHandle) dtype() DType {
	return DType(h.tensor.DType())
}

func (h *cgoTensorHandle) toHost(dst []byte) error {
	return h.tensor.ToHost(dst)
}

func (h *cgoTensorHandle) fromHost(src []byte) error {
	return h.tensor.FromHost(src)
}

func (h *cgoTensorHandle) destroy() {
	h.tensor.Destroy()
}

func (h *cgoTensorHandle) rawHandle() uintptr {
	return h.tensor.HandlePtr()
}

// capiTensor returns the underlying capi.Tensor for ops.
func (h *cgoTensorHandle) capiTensor() *capi.Tensor {
	return h.tensor
}

// getCAPITensor extracts capi.Tensor from UntypedTensor.
func getCAPITensor(t *UntypedTensor) *capi.Tensor {
	if t == nil || t.handle == nil {
		return nil
	}
	if h, ok := t.handle.(*cgoTensorHandle); ok {
		return h.tensor
	}
	return nil
}
