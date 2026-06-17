package accel

// FHEOps provides GPU-accelerated fully homomorphic encryption operations.
// Supports BFV (exact arithmetic) and CKKS (approximate arithmetic) schemes.
type FHEOps interface {
	// BFVEncrypt encrypts plaintext with BFV scheme.
	// plaintext: [N] int64 values (N ≤ poly_modulus_degree)
	// pk: public key
	// ciphertext: output ciphertext
	BFVEncrypt(plaintext, pk, ciphertext *UntypedTensor) error

	// BFVEncryptBatch encrypts multiple plaintexts.
	// plaintexts: [M, N] int64
	// pk: public key
	// ciphertexts: [M, ...] output
	BFVEncryptBatch(plaintexts, pk, ciphertexts *UntypedTensor) error

	// BFVDecrypt decrypts ciphertext.
	// ciphertext: input ciphertext
	// sk: secret key
	// plaintext: [N] int64 output
	BFVDecrypt(ciphertext, sk, plaintext *UntypedTensor) error

	// BFVAdd adds two ciphertexts.
	// ct1, ct2: input ciphertexts
	// result: output ciphertext
	BFVAdd(ct1, ct2, result *UntypedTensor) error

	// BFVMultiply multiplies ciphertexts with relinearization.
	// ct1, ct2: input ciphertexts
	// relinKey: relinearization key
	// result: output ciphertext
	BFVMultiply(ct1, ct2, relinKey, result *UntypedTensor) error

	// BFVMultiplyPlain multiplies ciphertext by plaintext.
	// ct: input ciphertext
	// plain: [N] int64 plaintext
	// result: output ciphertext
	BFVMultiplyPlain(ct, plain, result *UntypedTensor) error

	// BFVRotate rotates ciphertext slots.
	// ct: input ciphertext
	// galoisKey: Galois key for rotation
	// steps: rotation amount (positive = left)
	// result: output ciphertext
	BFVRotate(ct, galoisKey *UntypedTensor, steps int, result *UntypedTensor) error

	// CKKSEncrypt encrypts with CKKS (approximate arithmetic).
	// plaintext: [N] float64 values
	// pk: public key
	// scale: encoding scale
	// ciphertext: output
	CKKSEncrypt(plaintext, pk *UntypedTensor, scale float64, ciphertext *UntypedTensor) error

	// CKKSDecrypt decrypts CKKS ciphertext.
	// ciphertext: input
	// sk: secret key
	// plaintext: [N] float64 output
	CKKSDecrypt(ciphertext, sk, plaintext *UntypedTensor) error

	// CKKSAdd adds two CKKS ciphertexts.
	CKKSAdd(ct1, ct2, result *UntypedTensor) error

	// CKKSMultiply multiplies CKKS ciphertexts.
	CKKSMultiply(ct1, ct2, relinKey, result *UntypedTensor) error

	// CKKSRescale rescales ciphertext after multiplication.
	CKKSRescale(ct, result *UntypedTensor) error

	// CKKSRotate rotates CKKS slots.
	CKKSRotate(ct, galoisKey *UntypedTensor, steps int, result *UntypedTensor) error

	// Bootstrap refreshes ciphertext noise level (limited support).
	Bootstrap(ct, bootstrapKey, result *UntypedTensor) error
}
