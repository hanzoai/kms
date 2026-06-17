//go:build !cgo

package accel

// GetCapabilities returns empty capabilities in non-CGO builds.
func GetCapabilities(backend BackendType) (*BackendCapabilities, error) {
	return &BackendCapabilities{
		Backend:    backend,
		Operations: make(map[OperationType]bool),
		Categories: make(map[string]bool),
	}, nil
}

// AllCapabilities returns empty map in non-CGO builds.
func AllCapabilities() map[BackendType]*BackendCapabilities {
	return make(map[BackendType]*BackendCapabilities)
}

// CompareBackends returns empty comparison in non-CGO builds.
func CompareBackends(op OperationType, iterations int) (*BackendComparison, error) {
	return &BackendComparison{
		Operation: op,
		Results:   make(map[BackendType]BenchmarkResult),
	}, ErrNoBackends
}

// SelectBestBackend returns ErrNoBackends in non-CGO builds.
func SelectBestBackend(ops []OperationType, preferPerformance bool) (BackendType, error) {
	return BackendAuto, ErrNoBackends
}

// PrintCapabilities prints nothing in non-CGO builds.
func PrintCapabilities() {}
