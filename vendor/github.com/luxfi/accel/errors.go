package accel

import "errors"

// Batch operation thresholds - minimum items for GPU acceleration to be worthwhile.
const (
	BLSBatchVerifyThreshold    = 64  // Min signatures for GPU batch verify
	BLSBatchAggregateThreshold = 128 // Min items for GPU aggregation
	HashBatchThreshold         = 32  // Min items for GPU batch hash
	NTTBatchThreshold          = 4   // Min polynomials for GPU batch NTT
	MSMBatchThreshold          = 64  // Min points for GPU MSM
	KyberBatchThreshold        = 8   // Min operations for GPU batch
	DilithiumBatchThreshold    = 8   // Min operations for GPU batch
)

// Kyber key and ciphertext sizes (ML-KEM-768)
const (
	KyberPublicKeySize  = 1184
	KyberSecretKeySize  = 2400
	KyberCiphertextSize = 1088
	KyberSharedKeySize  = 32
)

// Dilithium sizes (ML-DSA-65)
const (
	DilithiumPublicKeySize = 1952
	DilithiumSecretKeySize = 4016
	DilithiumSignatureSize = 3309
)

var (
	// ErrNoBackends indicates no GPU backends are available.
	ErrNoBackends = errors.New("accel: no GPU backends available")

	// ErrNotInitialized indicates the library was not initialized.
	ErrNotInitialized = errors.New("accel: library not initialized")

	// ErrInvalidArgument indicates an invalid argument was provided.
	ErrInvalidArgument = errors.New("accel: invalid argument")

	// ErrOutOfMemory indicates GPU memory allocation failed.
	ErrOutOfMemory = errors.New("accel: out of GPU memory")

	// ErrNotSupported indicates the operation is not supported.
	ErrNotSupported = errors.New("accel: operation not supported")

	// ErrKernelFailed indicates a GPU kernel execution failed.
	ErrKernelFailed = errors.New("accel: kernel execution failed")

	// ErrBackendNotFound indicates the requested backend is not available.
	ErrBackendNotFound = errors.New("accel: backend not found")

	// ErrSessionClosed indicates the session has been closed.
	ErrSessionClosed = errors.New("accel: session closed")

	// ErrShapeMismatch indicates tensor shapes are incompatible.
	ErrShapeMismatch = errors.New("accel: tensor shape mismatch")

	// ErrBatchSizeMismatch indicates mismatched batch input sizes.
	ErrBatchSizeMismatch = errors.New("accel: mismatched batch input sizes")

	// ErrNilInput indicates nil input in batch operation.
	ErrNilInput = errors.New("accel: nil input in batch operation")
)

// Error wraps an error with additional context from the C library.
type Error struct {
	Op      string // Operation that failed
	Backend BackendType
	Err     error
	Detail  string // Additional detail from C library
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Op + ": " + e.Err.Error() + ": " + e.Detail
	}
	return e.Op + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error {
	return e.Err
}

// newError creates a new Error with the given operation and underlying error.
func newError(op string, err error) *Error {
	return &Error{Op: op, Err: err}
}

// newErrorWithDetail creates a new Error with detail message.
func newErrorWithDetail(op string, err error, detail string) *Error {
	return &Error{Op: op, Err: err, Detail: detail}
}
