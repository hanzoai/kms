package accel

// LatticeOps provides GPU-accelerated lattice-based cryptography operations.
// Implements NIST post-quantum standards: ML-KEM (Kyber) and ML-DSA (Dilithium).
type LatticeOps interface {
	// KyberKeyGen generates Kyber (ML-KEM) key pair.
	// pk: [1184] bytes (Kyber768 public key)
	// sk: [2400] bytes (Kyber768 secret key)
	KyberKeyGen(pk, sk *UntypedTensor) error

	// KyberKeyGenBatch generates multiple key pairs in parallel.
	// pk: [N, 1184] bytes
	// sk: [N, 2400] bytes
	KyberKeyGenBatch(pk, sk *UntypedTensor) error

	// KyberEncaps encapsulates shared secret.
	// pk: [1184] bytes public key
	// ct: [1088] bytes ciphertext output
	// ss: [32] bytes shared secret output
	KyberEncaps(pk, ct, ss *UntypedTensor) error

	// KyberEncapsBatch performs batch encapsulation.
	// pk: [N, 1184] bytes
	// ct: [N, 1088] bytes
	// ss: [N, 32] bytes
	KyberEncapsBatch(pk, ct, ss *UntypedTensor) error

	// KyberDecaps decapsulates shared secret.
	// ct: [1088] bytes ciphertext
	// sk: [2400] bytes secret key
	// ss: [32] bytes shared secret output
	KyberDecaps(ct, sk, ss *UntypedTensor) error

	// KyberDecapsBatch performs batch decapsulation.
	// ct: [N, 1088] bytes
	// sk: [N, 2400] bytes
	// ss: [N, 32] bytes
	KyberDecapsBatch(ct, sk, ss *UntypedTensor) error

	// DilithiumKeyGen generates Dilithium (ML-DSA) key pair.
	// pk: [1952] bytes (Dilithium3 public key)
	// sk: [4016] bytes (Dilithium3 secret key)
	DilithiumKeyGen(pk, sk *UntypedTensor) error

	// DilithiumSign signs a message.
	// msg: [msg_len] bytes message
	// sk: [4016] bytes secret key
	// sig: [3293] bytes signature output
	DilithiumSign(msg, sk, sig *UntypedTensor) error

	// DilithiumSignBatch signs multiple messages in parallel.
	// msgs: [N, msg_len] bytes
	// sk: [4016] bytes (same key for all)
	// sigs: [N, 3293] bytes
	DilithiumSignBatch(msgs, sk, sigs *UntypedTensor) error

	// DilithiumVerify verifies a signature.
	// msg: [msg_len] bytes
	// sig: [3293] bytes
	// pk: [1952] bytes
	// Returns true if valid.
	DilithiumVerify(msg, sig, pk *UntypedTensor) (bool, error)

	// DilithiumVerifyBatch verifies multiple signatures.
	// msgs: [N, msg_len] bytes
	// sigs: [N, 3293] bytes
	// pks: [N, 1952] bytes
	// results: [N] uint8 (1 = valid, 0 = invalid)
	DilithiumVerifyBatch(msgs, sigs, pks, results *UntypedTensor) error

	// PolynomialNTT performs NTT in lattice polynomial ring.
	// Operates on polynomials in Z_q[X]/(X^256 + 1).
	PolynomialNTT(input, output *UntypedTensor, q uint32) error

	// PolynomialINTT performs inverse NTT.
	PolynomialINTT(input, output *UntypedTensor, q uint32) error

	// PolynomialMul multiplies polynomials in NTT domain.
	PolynomialMul(a, b, c *UntypedTensor, q uint32) error

	// PolynomialAdd adds polynomials.
	PolynomialAdd(a, b, c *UntypedTensor, q uint32) error
}
