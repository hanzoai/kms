//go:build cgo

// Package capi provides CGO bindings to the lux-accel C library.
//
// Library resolution order:
//  1. System paths (/usr/local/lib, /usr/lib)
//  2. Homebrew paths (/opt/homebrew/lib)
//  3. Local luxcpp install (../../../luxcpp/install/lib)
//
// Install the library using one of:
//   - make install-system (from lux/accel)
//   - make build-deps && make install-system (build from luxcpp source)
//   - scripts/fetch-luxcpp.sh accel (download pre-built)
package capi

/*
// System and homebrew paths for headers
#cgo CFLAGS: -I/usr/local/include -I/opt/homebrew/include -I${SRCDIR}/../../include

// Fallback to local luxcpp install (relative to this file)
#cgo CFLAGS: -I${SRCDIR}/../../../../luxcpp/install/include

// macOS: system paths, homebrew, and local luxcpp with rpaths
#cgo darwin LDFLAGS: -L/usr/local/lib -L/opt/homebrew/lib
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../../luxcpp/install/lib
#cgo darwin LDFLAGS: -Wl,-rpath,/usr/local/lib -Wl,-rpath,/opt/homebrew/lib
#cgo darwin LDFLAGS: -Wl,-rpath,${SRCDIR}/../../../../luxcpp/install/lib
// Real library: set CGO_LDFLAGS=-lluxaccel when libluxaccel is installed

// Linux: system paths and local luxcpp with rpaths
#cgo linux LDFLAGS: -L/usr/local/lib -L/usr/lib
#cgo linux LDFLAGS: -L${SRCDIR}/../../../../luxcpp/install/lib
#cgo linux LDFLAGS: -Wl,-rpath,/usr/local/lib
#cgo linux LDFLAGS: -Wl,-rpath,${SRCDIR}/../../../../luxcpp/install/lib
// Real library: set CGO_LDFLAGS=-lluxaccel when libluxaccel is installed

#include <lux/accel/c_api.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

var (
	initOnce sync.Once
	initErr  error
)

// Error types matching C library status codes.
var (
	ErrOutOfMemory     = errors.New("out of memory")
	ErrInvalidArgument = errors.New("invalid argument")
	ErrNotSupported    = errors.New("not supported")
	ErrNoBackends      = errors.New("no backends")
	ErrKernelFailed    = errors.New("kernel failed")
)

// Init initializes the lux-accel library.
func Init() error {
	initOnce.Do(func() {
		status := C.lux_init()
		if status != C.LUX_OK {
			initErr = statusToError(status)
		}
	})
	return initErr
}

// Shutdown releases library resources.
func Shutdown() {
	C.lux_shutdown()
}

// Version returns the library version.
func Version() string {
	return C.GoString(C.lux_version())
}

// GetError returns the last error message.
func GetError() string {
	return C.GoString(C.lux_get_error())
}

// LoadBackend loads a backend plugin from path.
func LoadBackend(path string) error {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	status := C.lux_load_backend(cpath)
	return statusToError(status)
}

// BackendCount returns the number of available backends.
func BackendCount() int {
	return int(C.lux_backend_count())
}

// BackendTypeAt returns the backend type at index.
func BackendTypeAt(index int) int {
	return int(C.lux_backend_type_at(C.int(index)))
}

// DeviceCount returns the number of devices for a backend.
func DeviceCount(backend int) int {
	return int(C.lux_device_count(C.lux_backend_type(backend)))
}

// DeviceInfo contains device information.
type DeviceInfo struct {
	Name             string
	Vendor           string
	Backend          int
	IsDiscrete       bool
	IsUnifiedMemory  bool
	TotalMemory      uint64
	MaxWorkgroupSize uint32
	SIMDWidth        uint32
}

// GetDeviceInfo retrieves device information.
func GetDeviceInfo(backend, index int) (*DeviceInfo, error) {
	var info C.lux_device_info

	status := C.lux_get_device_info(C.lux_backend_type(backend), C.int(index), &info)
	if status != C.LUX_OK {
		return nil, statusToError(status)
	}

	return &DeviceInfo{
		Name:             C.GoString(info.name),
		Vendor:           C.GoString(info.vendor),
		Backend:          int(info.backend),
		IsDiscrete:       info.is_discrete != 0,
		IsUnifiedMemory:  info.is_unified_memory != 0,
		TotalMemory:      uint64(info.total_memory),
		MaxWorkgroupSize: uint32(info.max_workgroup_size),
		SIMDWidth:        uint32(info.simd_width),
	}, nil
}

// Session wraps a C session handle.
type Session struct {
	handle C.lux_session
}

// CreateSession creates a new session.
func CreateSession() (*Session, error) {
	var handle C.lux_session
	status := C.lux_session_create(&handle)
	if status != C.LUX_OK {
		return nil, statusToError(status)
	}
	return &Session{handle: handle}, nil
}

// CreateSessionWithBackend creates a session with specific backend.
func CreateSessionWithBackend(backend int) (*Session, error) {
	var handle C.lux_session
	status := C.lux_session_create_with_backend(C.lux_backend_type(backend), &handle)
	if status != C.LUX_OK {
		return nil, statusToError(status)
	}
	return &Session{handle: handle}, nil
}

// CreateSessionWithDevice creates a session with specific device.
func CreateSessionWithDevice(backend, deviceIndex int) (*Session, error) {
	var handle C.lux_session
	status := C.lux_session_create_with_device(
		C.lux_backend_type(backend),
		C.int(deviceIndex),
		&handle,
	)
	if status != C.LUX_OK {
		return nil, statusToError(status)
	}
	return &Session{handle: handle}, nil
}

// Destroy releases session resources.
func (s *Session) Destroy() {
	if s.handle != nil {
		C.lux_session_destroy(s.handle)
		s.handle = nil
	}
}

// Sync synchronizes all pending operations.
func (s *Session) Sync() error {
	status := C.lux_session_sync(s.handle)
	return statusToError(status)
}

// Handle returns the raw C handle.
func (s *Session) Handle() C.lux_session {
	return s.handle
}

// Tensor wraps a C tensor handle.
type Tensor struct {
	handle C.lux_tensor
}

// CreateTensor creates a new tensor.
func CreateTensor(session *Session, dtype int, shape []int) (*Tensor, error) {
	if len(shape) == 0 {
		return nil, ErrInvalidArgument
	}

	cshape := make([]C.size_t, len(shape))
	for i, s := range shape {
		cshape[i] = C.size_t(s)
	}

	var handle C.lux_tensor
	status := C.lux_tensor_create(
		session.handle,
		C.lux_dtype(dtype),
		&cshape[0],
		C.size_t(len(shape)),
		&handle,
	)
	if status != C.LUX_OK {
		return nil, statusToError(status)
	}
	return &Tensor{handle: handle}, nil
}

// CreateTensorWithData creates a tensor with initial data.
func CreateTensorWithData(session *Session, dtype int, shape []int, data []byte) (*Tensor, error) {
	if len(shape) == 0 || len(data) == 0 {
		return nil, ErrInvalidArgument
	}

	cshape := make([]C.size_t, len(shape))
	for i, s := range shape {
		cshape[i] = C.size_t(s)
	}

	var handle C.lux_tensor
	status := C.lux_tensor_create_with_data(
		session.handle,
		C.lux_dtype(dtype),
		&cshape[0],
		C.size_t(len(shape)),
		unsafe.Pointer(&data[0]),
		C.size_t(len(data)),
		&handle,
	)
	if status != C.LUX_OK {
		return nil, statusToError(status)
	}
	return &Tensor{handle: handle}, nil
}

// Destroy releases tensor resources.
func (t *Tensor) Destroy() {
	if t.handle != nil {
		C.lux_tensor_destroy(t.handle)
		t.handle = nil
	}
}

// NDim returns the number of dimensions.
func (t *Tensor) NDim() int {
	return int(C.lux_tensor_ndim(t.handle))
}

// Shape returns the size of a dimension.
func (t *Tensor) Shape(dim int) int {
	return int(C.lux_tensor_shape(t.handle, C.size_t(dim)))
}

// NumEl returns the total number of elements.
func (t *Tensor) NumEl() int {
	return int(C.lux_tensor_numel(t.handle))
}

// Bytes returns the total byte size.
func (t *Tensor) Bytes() int {
	return int(C.lux_tensor_bytes(t.handle))
}

// DType returns the data type.
func (t *Tensor) DType() int {
	return int(C.lux_tensor_dtype(t.handle))
}

// ToHost copies data to host memory.
func (t *Tensor) ToHost(dst []byte) error {
	status := C.lux_tensor_to_host(t.handle, unsafe.Pointer(&dst[0]), C.size_t(len(dst)))
	return statusToError(status)
}

// FromHost copies data from host memory.
func (t *Tensor) FromHost(src []byte) error {
	status := C.lux_tensor_from_host(t.handle, unsafe.Pointer(&src[0]), C.size_t(len(src)))
	return statusToError(status)
}

// Handle returns the raw C handle.
func (t *Tensor) Handle() C.lux_tensor {
	return t.handle
}

// HandlePtr returns the handle as uintptr.
func (t *Tensor) HandlePtr() uintptr {
	return uintptr(unsafe.Pointer(t.handle))
}

// statusToError converts C status to Go error.
func statusToError(status C.lux_status) error {
	switch status {
	case C.LUX_OK:
		return nil
	case C.LUX_ERROR:
		return fmt.Errorf("lux error: %s", GetError())
	case C.LUX_OUT_OF_MEMORY:
		return ErrOutOfMemory
	case C.LUX_INVALID_ARGUMENT:
		return ErrInvalidArgument
	case C.LUX_NOT_SUPPORTED:
		return ErrNotSupported
	case C.LUX_NO_BACKEND:
		return ErrNoBackends
	case C.LUX_KERNEL_ERROR:
		return ErrKernelFailed
	default:
		return fmt.Errorf("unknown lux error: %d", status)
	}
}

// ML operations

// MatMul performs matrix multiplication.
func MatMul(session *Session, a, b, c *Tensor) error {
	status := C.lux_matmul(session.handle, a.handle, b.handle, c.handle)
	return statusToError(status)
}

// ReLU applies ReLU activation.
func ReLU(session *Session, input, output *Tensor) error {
	status := C.lux_relu(session.handle, input.handle, output.handle)
	return statusToError(status)
}

// GELU applies GELU activation.
func GELU(session *Session, input, output *Tensor) error {
	status := C.lux_gelu(session.handle, input.handle, output.handle)
	return statusToError(status)
}

// Softmax applies softmax.
func Softmax(session *Session, input, output *Tensor, axis int) error {
	status := C.lux_softmax(session.handle, input.handle, output.handle, C.int(axis))
	return statusToError(status)
}

// LayerNorm applies layer normalization.
func LayerNorm(session *Session, input, gamma, beta, output *Tensor, eps float32) error {
	status := C.lux_layer_norm(session.handle, input.handle, gamma.handle, beta.handle, output.handle, C.float(eps))
	return statusToError(status)
}

// Attention computes attention.
func Attention(session *Session, q, k, v, output *Tensor, scale float32) error {
	status := C.lux_attention(session.handle, q.handle, k.handle, v.handle, output.handle, C.float(scale))
	return statusToError(status)
}

// Crypto operations

// SHA256 computes SHA-256.
func SHA256(session *Session, input, output *Tensor) error {
	status := C.lux_sha256(session.handle, input.handle, output.handle)
	return statusToError(status)
}

// Keccak256 computes Keccak-256.
func Keccak256(session *Session, input, output *Tensor) error {
	status := C.lux_keccak256(session.handle, input.handle, output.handle)
	return statusToError(status)
}

// Poseidon computes Poseidon hash.
func Poseidon(session *Session, input, output *Tensor) error {
	status := C.lux_poseidon(session.handle, input.handle, output.handle)
	return statusToError(status)
}

// ECDSAVerifyBatch verifies ECDSA signatures.
func ECDSAVerifyBatch(session *Session, messages, signatures, pubkeys, results *Tensor) error {
	status := C.lux_ecdsa_verify_batch(session.handle, messages.handle, signatures.handle, pubkeys.handle, results.handle)
	return statusToError(status)
}

// Ed25519VerifyBatch verifies Ed25519 signatures.
func Ed25519VerifyBatch(session *Session, messages, signatures, pubkeys, results *Tensor) error {
	status := C.lux_ed25519_verify_batch(session.handle, messages.handle, signatures.handle, pubkeys.handle, results.handle)
	return statusToError(status)
}

// BLSVerifyBatch verifies BLS signatures.
func BLSVerifyBatch(session *Session, messages, signatures, pubkeys, results *Tensor) error {
	status := C.lux_bls_verify_batch(session.handle, messages.handle, signatures.handle, pubkeys.handle, results.handle)
	return statusToError(status)
}

// MerkleRoot computes Merkle root.
func MerkleRoot(session *Session, leaves, root *Tensor) error {
	status := C.lux_merkle_root(session.handle, leaves.handle, root.handle)
	return statusToError(status)
}

// ZK operations

// NTT performs Number Theoretic Transform.
func NTT(session *Session, input, output, roots *Tensor, modulus uint64) error {
	status := C.lux_ntt(session.handle, input.handle, output.handle, roots.handle, C.uint64_t(modulus))
	return statusToError(status)
}

// INTT performs inverse NTT.
func INTT(session *Session, input, output, invRoots *Tensor, modulus uint64) error {
	status := C.lux_intt(session.handle, input.handle, output.handle, invRoots.handle, C.uint64_t(modulus))
	return statusToError(status)
}

// MSM performs multi-scalar multiplication.
func MSM(session *Session, scalars, bases, result *Tensor) error {
	status := C.lux_msm(session.handle, scalars.handle, bases.handle, result.handle)
	return statusToError(status)
}

// PolyMul multiplies polynomials.
func PolyMul(session *Session, a, b, c *Tensor, modulus uint64) error {
	status := C.lux_poly_mul(session.handle, a.handle, b.handle, c.handle, C.uint64_t(modulus))
	return statusToError(status)
}

// Lattice operations

// KyberKeyGen generates Kyber key pair.
func KyberKeyGen(session *Session, pk, sk *Tensor) error {
	status := C.lux_kyber_keygen(session.handle, pk.handle, sk.handle)
	return statusToError(status)
}

// KyberEncaps encapsulates shared secret.
func KyberEncaps(session *Session, pk, ct, ss *Tensor) error {
	status := C.lux_kyber_encaps(session.handle, pk.handle, ct.handle, ss.handle)
	return statusToError(status)
}

// KyberDecaps decapsulates shared secret.
func KyberDecaps(session *Session, ct, sk, ss *Tensor) error {
	status := C.lux_kyber_decaps(session.handle, ct.handle, sk.handle, ss.handle)
	return statusToError(status)
}

// DilithiumSign signs a message.
func DilithiumSign(session *Session, msg, sk, sig *Tensor) error {
	status := C.lux_dilithium_sign(session.handle, msg.handle, sk.handle, sig.handle)
	return statusToError(status)
}

// DilithiumVerify verifies a signature.
func DilithiumVerify(session *Session, msg, sig, pk *Tensor) (bool, error) {
	var valid C.int
	status := C.lux_dilithium_verify(session.handle, msg.handle, sig.handle, pk.handle, &valid)
	if err := statusToError(status); err != nil {
		return false, err
	}
	return valid != 0, nil
}

// FHE operations

// BFVEncrypt encrypts with BFV.
func BFVEncrypt(session *Session, plaintext, pk, ciphertext *Tensor) error {
	status := C.lux_bfv_encrypt(session.handle, plaintext.handle, pk.handle, ciphertext.handle)
	return statusToError(status)
}

// BFVDecrypt decrypts BFV.
func BFVDecrypt(session *Session, ciphertext, sk, plaintext *Tensor) error {
	status := C.lux_bfv_decrypt(session.handle, ciphertext.handle, sk.handle, plaintext.handle)
	return statusToError(status)
}

// BFVAdd adds BFV ciphertexts.
func BFVAdd(session *Session, ct1, ct2, result *Tensor) error {
	status := C.lux_bfv_add(session.handle, ct1.handle, ct2.handle, result.handle)
	return statusToError(status)
}

// BFVMultiply multiplies BFV ciphertexts.
func BFVMultiply(session *Session, ct1, ct2, relinKey, result *Tensor) error {
	status := C.lux_bfv_multiply(session.handle, ct1.handle, ct2.handle, relinKey.handle, result.handle)
	return statusToError(status)
}

// DEX operations

// ConstantProductSwap computes AMM swap.
func ConstantProductSwap(session *Session, reserveX, reserveY, amountIn, amountOut *Tensor, xToY bool, fee float32) error {
	var dir C.int
	if xToY {
		dir = 1
	}
	status := C.lux_constant_product_swap(session.handle, reserveX.handle, reserveY.handle, amountIn.handle, dir, amountOut.handle, C.float(fee))
	return statusToError(status)
}

// ComputeTWAP computes time-weighted average price.
func ComputeTWAP(session *Session, prices, timestamps, twap *Tensor, start, end uint64) error {
	status := C.lux_compute_twap(session.handle, prices.handle, timestamps.handle, C.uint64_t(start), C.uint64_t(end), twap.handle)
	return statusToError(status)
}

// MatchOrders matches orders.
func MatchOrders(session *Session, bids, asks, matches, prices, amounts *Tensor) error {
	status := C.lux_match_orders(session.handle, bids.handle, asks.handle, matches.handle, prices.handle, amounts.handle)
	return statusToError(status)
}
