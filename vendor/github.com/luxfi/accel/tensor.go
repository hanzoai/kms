//go:build !cgo

package accel

// stubTensorHandle implements tensorHandle for pure Go builds.
type stubTensorHandle struct{}

func (h *stubTensorHandle) ndim() int                 { return 0 }
func (h *stubTensorHandle) shape(dim int) int         { return 0 }
func (h *stubTensorHandle) numel() int                { return 0 }
func (h *stubTensorHandle) bytes() int                { return 0 }
func (h *stubTensorHandle) dtype() DType              { return Float32 }
func (h *stubTensorHandle) toHost(dst []byte) error   { return ErrNoBackends }
func (h *stubTensorHandle) fromHost(src []byte) error { return ErrNoBackends }
func (h *stubTensorHandle) destroy()                  {}
func (h *stubTensorHandle) rawHandle() uintptr        { return 0 }
