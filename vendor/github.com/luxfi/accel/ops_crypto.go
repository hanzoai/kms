package accel

// CryptoOps provides GPU-accelerated cryptographic operations.
type CryptoOps interface {
	// SHA256 computes SHA-256 hashes for a batch of inputs.
	// input: [N, input_len] bytes
	// output: [N, 32] bytes
	SHA256(input, output *UntypedTensor) error

	// Keccak256 computes Keccak-256 (Ethereum hash) for a batch.
	// input: [N, input_len] bytes
	// output: [N, 32] bytes
	Keccak256(input, output *UntypedTensor) error

	// Poseidon computes Poseidon hash (ZK-friendly).
	// input: [N, field_elements] uint64
	// output: [N, 1] uint64
	Poseidon(input, output *UntypedTensor) error

	// ECDSAVerifyBatch verifies multiple ECDSA signatures in parallel.
	// messages: [N, 32] bytes (message hashes)
	// signatures: [N, 64] bytes (r || s)
	// pubkeys: [N, 33] bytes (compressed) or [N, 65] (uncompressed)
	// results: [N] uint8 (1 = valid, 0 = invalid)
	ECDSAVerifyBatch(messages, signatures, pubkeys, results *UntypedTensor) error

	// Ed25519VerifyBatch verifies multiple Ed25519 signatures.
	// messages: [N, msg_len] bytes
	// signatures: [N, 64] bytes
	// pubkeys: [N, 32] bytes
	// results: [N] uint8 (1 = valid, 0 = invalid)
	Ed25519VerifyBatch(messages, signatures, pubkeys, results *UntypedTensor) error

	// BLSVerifyBatch verifies multiple BLS signatures.
	// messages: [N, msg_len] bytes
	// signatures: [N, 96] bytes (G2 points)
	// pubkeys: [N, 48] bytes (G1 points)
	// results: [N] uint8 (1 = valid, 0 = invalid)
	BLSVerifyBatch(messages, signatures, pubkeys, results *UntypedTensor) error

	// BLSAggregate aggregates multiple BLS signatures into one.
	// signatures: [N, 96] bytes
	// aggregated: [96] bytes
	BLSAggregate(signatures, aggregated *UntypedTensor) error

	// MerkleRoot computes Merkle root from leaves.
	// leaves: [N, 32] bytes (N must be power of 2)
	// root: [32] bytes
	MerkleRoot(leaves, root *UntypedTensor) error

	// MerkleBatch computes multiple Merkle roots in parallel.
	// leavesSet: [M, N, 32] bytes
	// roots: [M, 32] bytes
	MerkleBatch(leavesSet, roots *UntypedTensor) error

	// MerkleProof generates Merkle proof for a leaf.
	// leaves: [N, 32] bytes
	// leafIndex: index of the leaf
	// proof: [log2(N), 32] bytes
	MerkleProof(leaves *UntypedTensor, leafIndex int, proof *UntypedTensor) error
}
