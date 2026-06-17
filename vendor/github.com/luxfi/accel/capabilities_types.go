package accel

import "time"

// OperationType identifies a type of compute operation.
type OperationType int

const (
	// ML Operations
	OpMatMul OperationType = iota
	OpReLU
	OpGELU
	OpSoftmax
	OpLayerNorm
	OpAttention

	// Crypto Operations
	OpSHA256
	OpKeccak256
	OpPoseidon
	OpECDSAVerify
	OpEd25519Verify
	OpBLSVerify
	OpMerkleRoot

	// ZK Operations
	OpNTT
	OpINTT
	OpMSM
	OpPolyMul

	// FHE Operations
	OpBFVEncrypt
	OpBFVDecrypt
	OpBFVAdd
	OpBFVMul

	// Lattice Operations
	OpKyberKeyGen
	OpKyberEncaps
	OpKyberDecaps
	OpDilithiumSign
	OpDilithiumVerify

	// DEX Operations
	OpConstantProductSwap
	OpTWAP
	OpOrderMatch

	opCount // Internal sentinel
)

// String returns the operation name.
func (o OperationType) String() string {
	names := []string{
		"matmul", "relu", "gelu", "softmax", "layer_norm", "attention",
		"sha256", "keccak256", "poseidon", "ecdsa_verify", "ed25519_verify", "bls_verify", "merkle_root",
		"ntt", "intt", "msm", "poly_mul",
		"bfv_encrypt", "bfv_decrypt", "bfv_add", "bfv_mul",
		"kyber_keygen", "kyber_encaps", "kyber_decaps", "dilithium_sign", "dilithium_verify",
		"swap", "twap", "order_match",
	}
	if int(o) < len(names) {
		return names[o]
	}
	return "unknown"
}

// Category returns the operation category.
func (o OperationType) Category() string {
	switch {
	case o <= OpAttention:
		return "ML"
	case o <= OpMerkleRoot:
		return "Crypto"
	case o <= OpPolyMul:
		return "ZK"
	case o <= OpBFVMul:
		return "FHE"
	case o <= OpDilithiumVerify:
		return "Lattice"
	case o <= OpOrderMatch:
		return "DEX"
	default:
		return "Unknown"
	}
}

// BackendCapabilities describes what operations a backend supports.
type BackendCapabilities struct {
	Backend    BackendType
	Operations map[OperationType]bool
	Categories map[string]bool
}

// Supports returns true if the backend supports the operation.
func (c *BackendCapabilities) Supports(op OperationType) bool {
	return c.Operations[op]
}

// SupportsCategory returns true if the backend supports any operation in the category.
func (c *BackendCapabilities) SupportsCategory(cat string) bool {
	return c.Categories[cat]
}

// SupportedOperations returns a list of supported operations.
func (c *BackendCapabilities) SupportedOperations() []OperationType {
	var ops []OperationType
	for op, supported := range c.Operations {
		if supported {
			ops = append(ops, op)
		}
	}
	return ops
}

// BenchmarkResult holds timing data for an operation.
type BenchmarkResult struct {
	Backend   BackendType
	Operation OperationType
	Duration  time.Duration
	Error     error
}

// BackendComparison holds benchmark results across backends.
type BackendComparison struct {
	Operation OperationType
	Results   map[BackendType]BenchmarkResult
	Fastest   BackendType
}
