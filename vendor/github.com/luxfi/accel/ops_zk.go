package accel

// ZKOps provides GPU-accelerated zero-knowledge proof operations.
type ZKOps interface {
	// NTT performs Number Theoretic Transform.
	// input: [N] uint64 coefficients
	// output: [N] uint64 NTT values
	// roots: [N] uint64 roots of unity
	// modulus: prime modulus
	NTT(input, output, roots *UntypedTensor, modulus uint64) error

	// INTT performs inverse NTT.
	// input: [N] uint64 NTT values
	// output: [N] uint64 coefficients
	// invRoots: [N] uint64 inverse roots of unity
	// modulus: prime modulus
	INTT(input, output, invRoots *UntypedTensor, modulus uint64) error

	// MSM performs multi-scalar multiplication on elliptic curves.
	// scalars: [N, scalar_size] bytes
	// bases: [N, point_size] bytes (affine points)
	// result: [point_size] bytes
	MSM(scalars, bases, result *UntypedTensor) error

	// MSMBatch performs multiple MSMs in parallel.
	// scalars: [M, N, scalar_size] bytes
	// bases: [M, N, point_size] bytes
	// results: [M, point_size] bytes
	MSMBatch(scalars, bases, results *UntypedTensor) error

	// PolyMul multiplies polynomials in coefficient form.
	// a: [N] uint64 coefficients
	// b: [N] uint64 coefficients
	// c: [2N-1] uint64 result coefficients
	// modulus: prime modulus
	PolyMul(a, b, c *UntypedTensor, modulus uint64) error

	// PolyEval evaluates polynomial at given points.
	// coeffs: [degree+1] uint64
	// points: [N] uint64
	// results: [N] uint64
	// modulus: prime modulus
	PolyEval(coeffs, points, results *UntypedTensor, modulus uint64) error

	// CommitPoly computes polynomial commitment (KZG).
	// coeffs: [degree+1, field_size] bytes
	// srs: structured reference string
	// commitment: [point_size] bytes
	CommitPoly(coeffs, srs, commitment *UntypedTensor) error

	// FFT performs Fast Fourier Transform (complex).
	// input: [N, 2] float32 (real, imag)
	// output: [N, 2] float32
	FFT(input, output *UntypedTensor) error

	// IFFT performs inverse FFT.
	IFFT(input, output *UntypedTensor) error

	// FieldAdd adds field elements.
	// a: [N] uint64
	// b: [N] uint64
	// c: [N] uint64
	// modulus: prime modulus
	FieldAdd(a, b, c *UntypedTensor, modulus uint64) error

	// FieldMul multiplies field elements.
	FieldMul(a, b, c *UntypedTensor, modulus uint64) error

	// FieldInv computes modular inverse.
	FieldInv(a, b *UntypedTensor, modulus uint64) error
}
