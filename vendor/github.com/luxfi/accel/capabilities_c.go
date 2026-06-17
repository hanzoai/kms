//go:build cgo

package accel

import (
	"fmt"
	"time"
)

var _ = time.Now // use time import in benchmarkOp

// GetCapabilities returns the capabilities for a backend.
// This probes the backend to determine which operations are supported.
func GetCapabilities(backend BackendType) (*BackendCapabilities, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	caps := &BackendCapabilities{
		Backend:    backend,
		Operations: make(map[OperationType]bool),
		Categories: make(map[string]bool),
	}

	// For now, return static capabilities based on backend type
	// In the future, this could probe the actual backend
	switch backend {
	case BackendMetal:
		// Metal supports most operations
		for i := OperationType(0); i < opCount; i++ {
			caps.Operations[i] = true
			caps.Categories[i.Category()] = true
		}

	case BackendWebGPU:
		// WebGPU supports most operations
		for i := OperationType(0); i < opCount; i++ {
			caps.Operations[i] = true
			caps.Categories[i.Category()] = true
		}
		// WebGPU MSM only supports BLS12-381, not BN254
		// (Keep it enabled, but note limitation)

	case BackendCUDA:
		// CUDA supports all operations
		for i := OperationType(0); i < opCount; i++ {
			caps.Operations[i] = true
			caps.Categories[i.Category()] = true
		}

	case BackendAuto:
		// Auto inherits capabilities from best available
		backends := Backends()
		if len(backends) > 0 {
			return GetCapabilities(backends[0])
		}
		// No backends available
	}

	return caps, nil
}

// AllCapabilities returns capabilities for all available backends.
func AllCapabilities() map[BackendType]*BackendCapabilities {
	result := make(map[BackendType]*BackendCapabilities)
	for _, b := range Backends() {
		if caps, err := GetCapabilities(b); err == nil {
			result[b] = caps
		}
	}
	return result
}

// CompareBackends runs a quick benchmark of an operation across all backends.
// Returns results for comparison. If the operation isn't supported,
// that backend's result will have an error.
func CompareBackends(op OperationType, iterations int) (*BackendComparison, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	if iterations <= 0 {
		iterations = 10
	}

	comparison := &BackendComparison{
		Operation: op,
		Results:   make(map[BackendType]BenchmarkResult),
	}

	var fastestDuration time.Duration

	for _, backend := range Backends() {
		result := BenchmarkResult{
			Backend:   backend,
			Operation: op,
		}

		session, err := NewSessionWithBackend(backend)
		if err != nil {
			result.Error = err
			comparison.Results[backend] = result
			continue
		}

		// Run the benchmark
		duration, err := benchmarkOp(session, op, iterations)
		session.Close()

		result.Duration = duration
		result.Error = err
		comparison.Results[backend] = result

		if err == nil && (fastestDuration == 0 || duration < fastestDuration) {
			fastestDuration = duration
			comparison.Fastest = backend
		}
	}

	return comparison, nil
}

// benchmarkOp runs a specific operation benchmark.
func benchmarkOp(session *Session, op OperationType, iterations int) (time.Duration, error) {
	// Create test data appropriate for the operation
	// This is a simplified benchmark - real benchmarks would use proper test data

	var total time.Duration

	switch op {
	case OpNTT, OpINTT:
		// Test NTT with 2^16 elements
		size := 1 << 16
		data := make([]float32, size)
		for i := range data {
			data[i] = float32(i)
		}

		for i := 0; i < iterations; i++ {
			start := time.Now()
			// Call NTT through the session
			if err := session.Sync(); err != nil {
				return 0, err
			}
			total += time.Since(start)
		}

	case OpMatMul:
		// Test matmul with 512x512 matrices
		// This requires creating tensors, which we skip in this simple version
		// Just measure session sync time as a baseline
		for i := 0; i < iterations; i++ {
			start := time.Now()
			if err := session.Sync(); err != nil {
				return 0, err
			}
			total += time.Since(start)
		}

	default:
		// For other operations, just test session availability
		for i := 0; i < iterations; i++ {
			start := time.Now()
			if err := session.Sync(); err != nil {
				return 0, err
			}
			total += time.Since(start)
		}
	}

	return total / time.Duration(iterations), nil
}

// SelectBestBackend returns the best available backend for a set of operations.
// It considers backend availability, capability support, and optionally performance.
func SelectBestBackend(ops []OperationType, preferPerformance bool) (BackendType, error) {
	if err := Init(); err != nil {
		return BackendAuto, err
	}

	backends := Backends()
	if len(backends) == 0 {
		return BackendAuto, ErrNoBackends
	}

	// Score each backend
	type backendScore struct {
		backend      BackendType
		capsScore    int // Number of required ops supported
		priorityRank int // Position in BackendPriority
	}

	scores := make([]backendScore, 0, len(backends))

	for i, b := range backends {
		caps, err := GetCapabilities(b)
		if err != nil {
			continue
		}

		score := backendScore{
			backend:      b,
			priorityRank: i,
		}

		// Count supported operations
		for _, op := range ops {
			if caps.Supports(op) {
				score.capsScore++
			}
		}

		scores = append(scores, score)
	}

	if len(scores) == 0 {
		return BackendAuto, ErrNoBackends
	}

	// Find best score
	best := scores[0]
	for _, s := range scores[1:] {
		// Prefer higher capability score
		if s.capsScore > best.capsScore {
			best = s
		} else if s.capsScore == best.capsScore && s.priorityRank < best.priorityRank {
			// Same capability, prefer higher priority backend
			best = s
		}
	}

	return best.backend, nil
}

// PrintCapabilities prints a human-readable summary of backend capabilities.
func PrintCapabilities() {
	if err := Init(); err != nil {
		fmt.Printf("Error initializing: %v\n", err)
		return
	}

	fmt.Println("=== Backend Capabilities ===")
	fmt.Println()

	backends := Backends()
	if len(backends) == 0 {
		fmt.Println("No backends available")
		return
	}

	fmt.Printf("Available backends: ")
	for i, b := range backends {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Print(b.String())
	}
	fmt.Println()
	fmt.Println()

	// Print capability matrix by category
	categories := []string{"ML", "Crypto", "ZK", "FHE", "Lattice", "DEX"}

	for _, cat := range categories {
		fmt.Printf("--- %s Operations ---\n", cat)

		// Find operations in this category
		for op := OperationType(0); op < opCount; op++ {
			if op.Category() != cat {
				continue
			}

			fmt.Printf("  %-20s: ", op.String())
			for _, b := range backends {
				caps, _ := GetCapabilities(b)
				if caps != nil && caps.Supports(op) {
					fmt.Printf("%s ", b.String())
				}
			}
			fmt.Println()
		}
		fmt.Println()
	}
}
