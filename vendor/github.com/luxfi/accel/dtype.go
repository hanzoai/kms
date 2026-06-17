package accel

// DType represents a tensor data type.
type DType int

const (
	Float32 DType = iota
	Float16
	Float64
	Int32
	Int64
	Uint8
	Uint32
	Uint64
)

// Size returns the byte size of a single element.
func (d DType) Size() int {
	switch d {
	case Float32, Int32, Uint32:
		return 4
	case Float16:
		return 2
	case Float64, Int64, Uint64:
		return 8
	case Uint8:
		return 1
	default:
		return 0
	}
}

// String returns the dtype name.
func (d DType) String() string {
	names := []string{"float32", "float16", "float64", "int32", "int64", "uint8", "uint32", "uint64"}
	if int(d) < len(names) {
		return names[d]
	}
	return "unknown"
}

// DTypeOf returns the DType for a Go type.
func DTypeOf[T TensorElement]() DType {
	var zero T
	switch any(zero).(type) {
	case float32:
		return Float32
	case float64:
		return Float64
	case int32:
		return Int32
	case int64:
		return Int64
	case uint8:
		return Uint8
	case uint32:
		return Uint32
	case uint64:
		return Uint64
	default:
		panic("unsupported tensor element type")
	}
}

// TensorElement is a type constraint for tensor element types.
type TensorElement interface {
	float32 | float64 | int32 | int64 | uint8 | uint32 | uint64
}
