// Package accel provides GPU-accelerated operations for blockchain and ML workloads.
//
// The package supports multiple GPU backends (Metal, WebGPU, CUDA) via runtime
// plugin discovery. When built without CGO or when no backends are available,
// operations return ErrNoBackends.
//
// # Architecture
//
// accel wraps the lux-accel C++ library which provides:
//   - ML operations: matmul, attention, convolution, normalization
//   - Crypto operations: batch signature verification, hashing, Merkle trees
//   - ZK operations: NTT, MSM, polynomial arithmetic
//   - Lattice crypto: Kyber, Dilithium post-quantum operations
//   - FHE operations: BFV/CKKS homomorphic encryption
//   - DEX operations: AMM swaps, TWAP, order matching
//
// # Backend Selection
//
// Backends are automatically detected and selected in this priority order:
//   - CUDA (NVIDIA GPUs)
//   - Metal (Apple Silicon)
//   - WebGPU (cross-platform fallback)
//
// You can override with environment variable LUX_BACKEND or via API:
//
//	session, _ := accel.NewSessionWithBackend(accel.BackendMetal)
//
// # Runtime Backend Selection
//
// For intelligent backend selection based on required operations:
//
//	// Select best backend for ZK operations
//	backend, _ := accel.SelectBackend(accel.OpNTT, accel.OpMSM)
//	session, _ := accel.NewSessionWithBackend(backend)
//
//	// Query capabilities
//	caps, _ := accel.Capabilities(accel.BackendWebGPU)
//	if caps.Supports(accel.OpMSM) {
//	    // Use MSM on WebGPU
//	}
//
//	// Compare backends for an operation
//	comparison, _ := accel.CompareBackends(accel.OpNTT, 10)
//	fmt.Printf("Fastest backend for NTT: %s\n", comparison.Fastest)
//
//	// Print all capabilities
//	accel.PrintCapabilities()
//
// # Pure Go Mode
//
// When built with CGO_ENABLED=0, the package compiles in pure Go mode.
// All operations return ErrNoBackends but the package remains importable,
// allowing graceful fallback to CPU implementations.
//
// # Basic Usage
//
//	// Initialize library
//	if err := accel.Init(); err != nil {
//	    log.Printf("GPU accel not available: %v", err)
//	}
//	defer accel.Shutdown()
//
//	// Check availability
//	if !accel.Available() {
//	    // Use CPU fallback
//	    return
//	}
//
//	// Create session
//	session, err := accel.NewSession()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer session.Close()
//
//	// Create tensors
//	a, _ := accel.NewTensor[float32](session, []int{1024, 1024})
//	b, _ := accel.NewTensor[float32](session, []int{1024, 1024})
//	c, _ := accel.NewTensor[float32](session, []int{1024, 1024})
//
//	// Perform GPU operation
//	if err := session.ML().MatMul(a.Untyped(), b.Untyped(), c.Untyped()); err != nil {
//	    log.Fatal(err)
//	}
//
// # Integration with Lux Node
//
// The accel package integrates with lux-node for:
//   - Batch signature verification in consensus
//   - Merkle tree computation for state sync
//   - Post-quantum cryptography for future-proofing
//
// See the node/consensus and precompile packages for integration examples.
package accel
