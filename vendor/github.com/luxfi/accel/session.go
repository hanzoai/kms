//go:build !cgo

package accel

import (
	"context"
)

func initLibrary() error {
	// No-op in pure Go mode - library compiles but no backends available
	return nil
}

func shutdown() {
	// No-op
}

func version() string {
	return Version + "-nocgo"
}

func lastError() string {
	return "no CGO support"
}

func backendCount() int {
	return 0
}

func deviceCountForBackend(b BackendType) int {
	return 0
}

func availableBackends() []BackendType {
	return nil
}

func allDevices() []DeviceInfo {
	return nil
}

func newSession(opts ...SessionOption) (*Session, error) {
	return nil, ErrNoBackends
}

func newSessionWithBackend(backend BackendType, opts ...SessionOption) (*Session, error) {
	return nil, ErrNoBackends
}

func newSessionWithDevice(backend BackendType, deviceIndex int, opts ...SessionOption) (*Session, error) {
	return nil, ErrNoBackends
}

// stubSessionHandle implements sessionHandle for pure Go builds.
type stubSessionHandle struct{}

func (h *stubSessionHandle) sync() error {
	return ErrNoBackends
}

func (h *stubSessionHandle) syncContext(ctx context.Context) error {
	return ErrNoBackends
}

func (h *stubSessionHandle) close() error {
	return nil
}

func (h *stubSessionHandle) ml() MLOps {
	return &stubMLOps{}
}

func (h *stubSessionHandle) crypto() CryptoOps {
	return &stubCryptoOps{}
}

func (h *stubSessionHandle) zk() ZKOps {
	return &stubZKOps{}
}

func (h *stubSessionHandle) lattice() LatticeOps {
	return &stubLatticeOps{}
}

func (h *stubSessionHandle) fhe() FHEOps {
	return &stubFHEOps{}
}

func (h *stubSessionHandle) dex() DEXOps {
	return &stubDEXOps{}
}

func (h *stubSessionHandle) createTensor(dtype DType, shape []int) (tensorHandle, error) {
	return nil, ErrNoBackends
}

func (h *stubSessionHandle) createTensorWithData(dtype DType, shape []int, data []byte) (tensorHandle, error) {
	return nil, ErrNoBackends
}
