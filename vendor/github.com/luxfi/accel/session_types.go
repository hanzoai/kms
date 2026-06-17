package accel

import (
	"context"
	"sync"
)

// SessionOption configures session creation.
type SessionOption func(*sessionConfig)

type sessionConfig struct {
	backend     BackendType
	deviceIndex int
	asyncMode   bool
}

// WithBackend specifies the backend to use.
func WithBackend(b BackendType) SessionOption {
	return func(c *sessionConfig) {
		c.backend = b
	}
}

// WithDevice specifies the device index within the backend.
func WithDevice(index int) SessionOption {
	return func(c *sessionConfig) {
		c.deviceIndex = index
	}
}

// WithAsync enables asynchronous operation mode.
func WithAsync(async bool) SessionOption {
	return func(c *sessionConfig) {
		c.asyncMode = async
	}
}

// Session manages a GPU acceleration context.
// All tensor operations must use tensors created from the same session.
// Session is safe for concurrent use.
type Session struct {
	mu     sync.RWMutex
	handle sessionHandle
	device DeviceInfo
	closed bool
}

// DeviceInfo returns information about the session's device.
func (s *Session) DeviceInfo() DeviceInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.device
}

// Backend returns the backend type for this session.
func (s *Session) Backend() BackendType {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.device.Backend
}

// Sync waits for all pending operations to complete.
func (s *Session) Sync() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrSessionClosed
	}
	return s.handle.sync()
}

// SyncContext waits for pending operations with context cancellation.
func (s *Session) SyncContext(ctx context.Context) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return ErrSessionClosed
	}
	h := s.handle
	s.mu.RUnlock()

	return h.syncContext(ctx)
}

// Close releases all session resources.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	return s.handle.close()
}

// IsClosed returns true if the session has been closed.
func (s *Session) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// ML returns the ML operations interface.
func (s *Session) ML() MLOps {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.handle.ml()
}

// Crypto returns the cryptographic operations interface.
func (s *Session) Crypto() CryptoOps {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.handle.crypto()
}

// ZK returns the zero-knowledge proof operations interface.
func (s *Session) ZK() ZKOps {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.handle.zk()
}

// Lattice returns the lattice cryptography operations interface.
func (s *Session) Lattice() LatticeOps {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.handle.lattice()
}

// FHE returns the fully homomorphic encryption operations interface.
func (s *Session) FHE() FHEOps {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.handle.fhe()
}

// DEX returns the decentralized exchange operations interface.
func (s *Session) DEX() DEXOps {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.handle.dex()
}

// sessionHandle is the internal interface implemented by CGO and pure Go.
type sessionHandle interface {
	sync() error
	syncContext(ctx context.Context) error
	close() error
	ml() MLOps
	crypto() CryptoOps
	zk() ZKOps
	lattice() LatticeOps
	fhe() FHEOps
	dex() DEXOps
	createTensor(dtype DType, shape []int) (tensorHandle, error)
	createTensorWithData(dtype DType, shape []int, data []byte) (tensorHandle, error)
}
