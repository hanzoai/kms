//go:build !cgo

package accel

// Stub implementations that return ErrNoBackends for all operations.
// These allow the package to compile without CGO while providing
// meaningful error messages at runtime.

type stubMLOps struct{}

func (o *stubMLOps) MatMul(a, b, c *UntypedTensor) error { return ErrNoBackends }
func (o *stubMLOps) MatMulTranspose(a, b, c *UntypedTensor, transposeA, transposeB bool) error {
	return ErrNoBackends
}
func (o *stubMLOps) ReLU(input, output *UntypedTensor) error              { return ErrNoBackends }
func (o *stubMLOps) GELU(input, output *UntypedTensor) error              { return ErrNoBackends }
func (o *stubMLOps) Softmax(input, output *UntypedTensor, axis int) error { return ErrNoBackends }
func (o *stubMLOps) LayerNorm(input, gamma, beta, output *UntypedTensor, eps float32) error {
	return ErrNoBackends
}
func (o *stubMLOps) Attention(q, k, v, output *UntypedTensor, scale float32) error {
	return ErrNoBackends
}
func (o *stubMLOps) Conv2D(input, kernel, output *UntypedTensor, stride, padding [2]int) error {
	return ErrNoBackends
}
func (o *stubMLOps) MaxPool2D(input, output *UntypedTensor, kernelSize, stride [2]int) error {
	return ErrNoBackends
}
func (o *stubMLOps) BatchNorm(input, gamma, beta, mean, variance, output *UntypedTensor, eps float32) error {
	return ErrNoBackends
}
func (o *stubMLOps) Dropout(input, output *UntypedTensor, p float32) error { return ErrNoBackends }
func (o *stubMLOps) Add(a, b, c *UntypedTensor) error                      { return ErrNoBackends }
func (o *stubMLOps) Multiply(a, b, c *UntypedTensor) error                 { return ErrNoBackends }
func (o *stubMLOps) Sum(input, output *UntypedTensor, axes []int) error    { return ErrNoBackends }
func (o *stubMLOps) Mean(input, output *UntypedTensor, axes []int) error   { return ErrNoBackends }

type stubCryptoOps struct{}

func (o *stubCryptoOps) SHA256(input, output *UntypedTensor) error    { return ErrNoBackends }
func (o *stubCryptoOps) Keccak256(input, output *UntypedTensor) error { return ErrNoBackends }
func (o *stubCryptoOps) Poseidon(input, output *UntypedTensor) error  { return ErrNoBackends }
func (o *stubCryptoOps) ECDSAVerifyBatch(messages, signatures, pubkeys, results *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubCryptoOps) Ed25519VerifyBatch(messages, signatures, pubkeys, results *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubCryptoOps) BLSVerifyBatch(messages, signatures, pubkeys, results *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubCryptoOps) BLSAggregate(signatures, aggregated *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubCryptoOps) MerkleRoot(leaves, root *UntypedTensor) error      { return ErrNoBackends }
func (o *stubCryptoOps) MerkleBatch(leavesSet, roots *UntypedTensor) error { return ErrNoBackends }
func (o *stubCryptoOps) MerkleProof(leaves *UntypedTensor, leafIndex int, proof *UntypedTensor) error {
	return ErrNoBackends
}

type stubZKOps struct{}

func (o *stubZKOps) NTT(input, output, roots *UntypedTensor, modulus uint64) error {
	return ErrNoBackends
}
func (o *stubZKOps) INTT(input, output, invRoots *UntypedTensor, modulus uint64) error {
	return ErrNoBackends
}
func (o *stubZKOps) MSM(scalars, bases, result *UntypedTensor) error       { return ErrNoBackends }
func (o *stubZKOps) MSMBatch(scalars, bases, results *UntypedTensor) error { return ErrNoBackends }
func (o *stubZKOps) PolyMul(a, b, c *UntypedTensor, modulus uint64) error  { return ErrNoBackends }
func (o *stubZKOps) PolyEval(coeffs, points, results *UntypedTensor, modulus uint64) error {
	return ErrNoBackends
}
func (o *stubZKOps) CommitPoly(coeffs, srs, commitment *UntypedTensor) error { return ErrNoBackends }
func (o *stubZKOps) FFT(input, output *UntypedTensor) error                  { return ErrNoBackends }
func (o *stubZKOps) IFFT(input, output *UntypedTensor) error                 { return ErrNoBackends }
func (o *stubZKOps) FieldAdd(a, b, c *UntypedTensor, modulus uint64) error   { return ErrNoBackends }
func (o *stubZKOps) FieldMul(a, b, c *UntypedTensor, modulus uint64) error   { return ErrNoBackends }
func (o *stubZKOps) FieldInv(a, b *UntypedTensor, modulus uint64) error      { return ErrNoBackends }

type stubLatticeOps struct{}

func (o *stubLatticeOps) KyberKeyGen(pk, sk *UntypedTensor) error          { return ErrNoBackends }
func (o *stubLatticeOps) KyberKeyGenBatch(pk, sk *UntypedTensor) error     { return ErrNoBackends }
func (o *stubLatticeOps) KyberEncaps(pk, ct, ss *UntypedTensor) error      { return ErrNoBackends }
func (o *stubLatticeOps) KyberEncapsBatch(pk, ct, ss *UntypedTensor) error { return ErrNoBackends }
func (o *stubLatticeOps) KyberDecaps(ct, sk, ss *UntypedTensor) error      { return ErrNoBackends }
func (o *stubLatticeOps) KyberDecapsBatch(ct, sk, ss *UntypedTensor) error { return ErrNoBackends }
func (o *stubLatticeOps) DilithiumKeyGen(pk, sk *UntypedTensor) error      { return ErrNoBackends }
func (o *stubLatticeOps) DilithiumSign(msg, sk, sig *UntypedTensor) error  { return ErrNoBackends }
func (o *stubLatticeOps) DilithiumSignBatch(msgs, sk, sigs *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubLatticeOps) DilithiumVerify(msg, sig, pk *UntypedTensor) (bool, error) {
	return false, ErrNoBackends
}
func (o *stubLatticeOps) DilithiumVerifyBatch(msgs, sigs, pks, results *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubLatticeOps) PolynomialNTT(input, output *UntypedTensor, q uint32) error {
	return ErrNoBackends
}
func (o *stubLatticeOps) PolynomialINTT(input, output *UntypedTensor, q uint32) error {
	return ErrNoBackends
}
func (o *stubLatticeOps) PolynomialMul(a, b, c *UntypedTensor, q uint32) error { return ErrNoBackends }
func (o *stubLatticeOps) PolynomialAdd(a, b, c *UntypedTensor, q uint32) error { return ErrNoBackends }

type stubFHEOps struct{}

func (o *stubFHEOps) BFVEncrypt(plaintext, pk, ciphertext *UntypedTensor) error { return ErrNoBackends }
func (o *stubFHEOps) BFVEncryptBatch(plaintexts, pk, ciphertexts *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubFHEOps) BFVDecrypt(ciphertext, sk, plaintext *UntypedTensor) error { return ErrNoBackends }
func (o *stubFHEOps) BFVAdd(ct1, ct2, result *UntypedTensor) error              { return ErrNoBackends }
func (o *stubFHEOps) BFVMultiply(ct1, ct2, relinKey, result *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubFHEOps) BFVMultiplyPlain(ct, plain, result *UntypedTensor) error { return ErrNoBackends }
func (o *stubFHEOps) BFVRotate(ct, galoisKey *UntypedTensor, steps int, result *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubFHEOps) CKKSEncrypt(plaintext, pk *UntypedTensor, scale float64, ciphertext *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubFHEOps) CKKSDecrypt(ciphertext, sk, plaintext *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubFHEOps) CKKSAdd(ct1, ct2, result *UntypedTensor) error { return ErrNoBackends }
func (o *stubFHEOps) CKKSMultiply(ct1, ct2, relinKey, result *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubFHEOps) CKKSRescale(ct, result *UntypedTensor) error { return ErrNoBackends }
func (o *stubFHEOps) CKKSRotate(ct, galoisKey *UntypedTensor, steps int, result *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubFHEOps) Bootstrap(ct, bootstrapKey, result *UntypedTensor) error { return ErrNoBackends }

type stubDEXOps struct{}

func (o *stubDEXOps) ConstantProductSwap(reserveX, reserveY, amountIn *UntypedTensor, xToY bool, amountOut *UntypedTensor, fee float32) error {
	return ErrNoBackends
}
func (o *stubDEXOps) ConstantProductSwapBatch(reserves, swaps, amounts *UntypedTensor, fee float32) error {
	return ErrNoBackends
}
func (o *stubDEXOps) ComputeTWAP(prices, timestamps *UntypedTensor, start, end uint64, twap *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubDEXOps) MatchOrders(bids, asks, matches, prices, amounts *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubDEXOps) MatchOrdersWithPriority(bids, asks, matches *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubDEXOps) ComputeLiquidity(tickLower, tickUpper, amounts, liquidity *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubDEXOps) ComputePositionValue(liquidity, tickLower, tickUpper *UntypedTensor, currentTick int32, values *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubDEXOps) CalculateFees(liquidity, feeGrowthInside0, feeGrowthInside1, fees *UntypedTensor) error {
	return ErrNoBackends
}
func (o *stubDEXOps) BatchSettlement(trades, balances, newBalances *UntypedTensor) error {
	return ErrNoBackends
}
