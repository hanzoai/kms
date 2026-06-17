package accel

import (
	"runtime"
	"unsafe"
)

// Tensor represents a multi-dimensional array on GPU memory.
// Tensor is not safe for concurrent modification but safe for concurrent reads.
type Tensor[T TensorElement] struct {
	handle  tensorHandle
	session *Session
	shape   []int
	dtype   DType
}

// tensorHandle is the internal interface for tensor operations.
type tensorHandle interface {
	ndim() int
	shape(dim int) int
	numel() int
	bytes() int
	dtype() DType
	toHost(dst []byte) error
	fromHost(src []byte) error
	destroy()
	rawHandle() uintptr
}

// NewTensor creates a new tensor with the given shape.
func NewTensor[T TensorElement](s *Session, shape []int) (*Tensor[T], error) {
	if s.IsClosed() {
		return nil, ErrSessionClosed
	}

	// Validate shape
	if len(shape) == 0 {
		return nil, newError("NewTensor", ErrInvalidArgument)
	}
	for _, dim := range shape {
		if dim <= 0 {
			return nil, newError("NewTensor", ErrInvalidArgument)
		}
	}

	dtype := DTypeOf[T]()
	h, err := s.handle.createTensor(dtype, shape)
	if err != nil {
		return nil, err
	}

	t := &Tensor[T]{
		handle:  h,
		session: s,
		shape:   append([]int(nil), shape...),
		dtype:   dtype,
	}

	// Set finalizer for cleanup if Close() not called
	runtime.SetFinalizer(t, func(t *Tensor[T]) { t.Close() })

	return t, nil
}

// NewTensorWithData creates a tensor initialized with data from a slice.
func NewTensorWithData[T TensorElement](s *Session, shape []int, data []T) (*Tensor[T], error) {
	if s.IsClosed() {
		return nil, ErrSessionClosed
	}

	// Validate shape dimensions
	if len(shape) == 0 {
		return nil, newError("NewTensorWithData", ErrInvalidArgument)
	}
	expectedSize := 1
	for _, dim := range shape {
		if dim <= 0 {
			return nil, newError("NewTensorWithData", ErrInvalidArgument)
		}
		expectedSize *= dim
	}

	// Validate data size
	if len(data) == 0 || len(data) != expectedSize {
		return nil, newError("NewTensorWithData", ErrInvalidArgument)
	}

	dtype := DTypeOf[T]()

	// Convert to bytes (safe now that we validated data is non-empty)
	dataBytes := unsafe.Slice((*byte)(unsafe.Pointer(&data[0])), len(data)*dtype.Size())

	h, err := s.handle.createTensorWithData(dtype, shape, dataBytes)
	if err != nil {
		return nil, err
	}

	t := &Tensor[T]{
		handle:  h,
		session: s,
		shape:   append([]int(nil), shape...),
		dtype:   dtype,
	}

	// Set finalizer for cleanup if Close() not called
	runtime.SetFinalizer(t, func(t *Tensor[T]) { t.Close() })

	return t, nil
}

// Shape returns a copy of the tensor shape.
func (t *Tensor[T]) Shape() []int {
	return append([]int(nil), t.shape...)
}

// NDim returns the number of dimensions.
func (t *Tensor[T]) NDim() int {
	return len(t.shape)
}

// NumEl returns the total number of elements.
func (t *Tensor[T]) NumEl() int {
	n := 1
	for _, s := range t.shape {
		n *= s
	}
	return n
}

// DType returns the element data type.
func (t *Tensor[T]) DType() DType {
	return t.dtype
}

// Bytes returns the total byte size.
func (t *Tensor[T]) Bytes() int {
	return t.NumEl() * t.dtype.Size()
}

// ToSlice copies tensor data to a Go slice.
func (t *Tensor[T]) ToSlice() ([]T, error) {
	if t.handle == nil {
		return nil, newError("ToSlice", ErrSessionClosed)
	}

	dst := make([]T, t.NumEl())
	dstBytes := unsafe.Slice((*byte)(unsafe.Pointer(&dst[0])), len(dst)*t.dtype.Size())
	if err := t.handle.toHost(dstBytes); err != nil {
		return nil, err
	}
	return dst, nil
}

// FromSlice copies data from a Go slice to the tensor.
func (t *Tensor[T]) FromSlice(src []T) error {
	if t.handle == nil {
		return newError("FromSlice", ErrSessionClosed)
	}

	if len(src) != t.NumEl() {
		return ErrInvalidArgument
	}
	srcBytes := unsafe.Slice((*byte)(unsafe.Pointer(&src[0])), len(src)*t.dtype.Size())
	return t.handle.fromHost(srcBytes)
}

// Close releases tensor resources.
func (t *Tensor[T]) Close() {
	if t.handle != nil {
		t.handle.destroy()
		t.handle = nil
	}
}

// Untyped returns an untyped view of the tensor for passing to ops.
func (t *Tensor[T]) Untyped() *UntypedTensor {
	return &UntypedTensor{
		handle: t.handle,
		shape:  t.shape,
		dtype:  t.dtype,
	}
}

// UntypedTensor provides type-erased tensor operations.
// Used internally and for dynamic typing scenarios.
type UntypedTensor struct {
	handle tensorHandle
	shape  []int
	dtype  DType
}

// Shape returns a copy of the tensor shape.
func (t *UntypedTensor) Shape() []int {
	return append([]int(nil), t.shape...)
}

// NDim returns the number of dimensions.
func (t *UntypedTensor) NDim() int {
	return len(t.shape)
}

// NumEl returns the total number of elements.
func (t *UntypedTensor) NumEl() int {
	n := 1
	for _, s := range t.shape {
		n *= s
	}
	return n
}

// DType returns the element data type.
func (t *UntypedTensor) DType() DType {
	return t.dtype
}

// Bytes returns the total byte size.
func (t *UntypedTensor) Bytes() int {
	return t.NumEl() * t.dtype.Size()
}

// Handle returns the raw tensor handle for CGO operations.
func (t *UntypedTensor) Handle() uintptr {
	if t.handle == nil {
		return 0
	}
	return t.handle.rawHandle()
}
