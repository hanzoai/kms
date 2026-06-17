package accel

// BackendType identifies a GPU compute backend.
type BackendType int

const (
	// BackendAuto selects the best available backend automatically.
	// Priority: CUDA > Metal > WebGPU
	BackendAuto BackendType = iota

	// BackendMetal uses Apple Metal (macOS/iOS).
	BackendMetal

	// BackendWebGPU uses WebGPU via Dawn (cross-platform).
	BackendWebGPU

	// BackendCUDA uses NVIDIA CUDA.
	BackendCUDA
)

// String returns the backend name.
func (b BackendType) String() string {
	switch b {
	case BackendAuto:
		return "auto"
	case BackendMetal:
		return "metal"
	case BackendWebGPU:
		return "webgpu"
	case BackendCUDA:
		return "cuda"
	default:
		return "unknown"
	}
}

// BackendInfo provides information about an available backend.
type BackendInfo struct {
	Type        BackendType
	Name        string
	APIVersion  int
	DeviceCount int
}

// BackendPriority defines the order for automatic backend selection.
var BackendPriority = []BackendType{
	BackendCUDA,  // Highest priority
	BackendMetal, // Apple Silicon
	BackendWebGPU,
}
