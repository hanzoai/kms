//go:build cgo

package accel

import (
	"github.com/luxfi/accel/internal/capi"
)

// CGO Backend Implementation
//
// The following operations are not yet exposed in the C API and return ErrNotSupported:
//
// ML: MatMulTranspose, Conv2D, MaxPool2D, BatchNorm, Dropout, Add, Multiply, Sum, Mean
// Crypto: BLSAggregate, MerkleBatch, MerkleProof
// ZK: MSMBatch, PolyEval, CommitPoly, FFT, IFFT, FieldAdd, FieldMul, FieldInv
// Lattice: KyberKeyGenBatch, KyberEncapsBatch, KyberDecapsBatch, DilithiumKeyGen,
//          DilithiumSignBatch, DilithiumVerifyBatch, PolynomialNTT, PolynomialINTT,
//          PolynomialMul, PolynomialAdd
// FHE: BFVEncryptBatch, BFVMultiplyPlain, BFVRotate, CKKSEncrypt, CKKSDecrypt,
//      CKKSAdd, CKKSMultiply, CKKSRescale, CKKSRotate, Bootstrap
// DEX: ConstantProductSwapBatch, MatchOrdersWithPriority, ComputeLiquidity,
//      ComputePositionValue, CalculateFees, BatchSettlement

// cgoMLOps implements MLOps using CGO.
type cgoMLOps struct {
	session *capi.Session
}

func (o *cgoMLOps) MatMul(a, b, c *UntypedTensor) error {
	return capi.MatMul(o.session, getCAPITensor(a), getCAPITensor(b), getCAPITensor(c))
}

func (o *cgoMLOps) MatMulTranspose(a, b, c *UntypedTensor, transposeA, transposeB bool) error {
	return ErrNotSupported
}

func (o *cgoMLOps) ReLU(input, output *UntypedTensor) error {
	return capi.ReLU(o.session, getCAPITensor(input), getCAPITensor(output))
}

func (o *cgoMLOps) GELU(input, output *UntypedTensor) error {
	return capi.GELU(o.session, getCAPITensor(input), getCAPITensor(output))
}

func (o *cgoMLOps) Softmax(input, output *UntypedTensor, axis int) error {
	return capi.Softmax(o.session, getCAPITensor(input), getCAPITensor(output), axis)
}

func (o *cgoMLOps) LayerNorm(input, gamma, beta, output *UntypedTensor, eps float32) error {
	return capi.LayerNorm(o.session, getCAPITensor(input), getCAPITensor(gamma), getCAPITensor(beta), getCAPITensor(output), eps)
}

func (o *cgoMLOps) Attention(q, k, v, output *UntypedTensor, scale float32) error {
	return capi.Attention(o.session, getCAPITensor(q), getCAPITensor(k), getCAPITensor(v), getCAPITensor(output), scale)
}

func (o *cgoMLOps) Conv2D(input, kernel, output *UntypedTensor, stride, padding [2]int) error {
	return ErrNotSupported
}

func (o *cgoMLOps) MaxPool2D(input, output *UntypedTensor, kernelSize, stride [2]int) error {
	return ErrNotSupported
}

func (o *cgoMLOps) BatchNorm(input, gamma, beta, mean, variance, output *UntypedTensor, eps float32) error {
	return ErrNotSupported
}

func (o *cgoMLOps) Dropout(input, output *UntypedTensor, p float32) error {
	return ErrNotSupported
}

func (o *cgoMLOps) Add(a, b, c *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoMLOps) Multiply(a, b, c *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoMLOps) Sum(input, output *UntypedTensor, axes []int) error {
	return ErrNotSupported
}

func (o *cgoMLOps) Mean(input, output *UntypedTensor, axes []int) error {
	return ErrNotSupported
}

// cgoCryptoOps implements CryptoOps using CGO.
type cgoCryptoOps struct {
	session *capi.Session
}

func (o *cgoCryptoOps) SHA256(input, output *UntypedTensor) error {
	return capi.SHA256(o.session, getCAPITensor(input), getCAPITensor(output))
}

func (o *cgoCryptoOps) Keccak256(input, output *UntypedTensor) error {
	return capi.Keccak256(o.session, getCAPITensor(input), getCAPITensor(output))
}

func (o *cgoCryptoOps) Poseidon(input, output *UntypedTensor) error {
	return capi.Poseidon(o.session, getCAPITensor(input), getCAPITensor(output))
}

func (o *cgoCryptoOps) ECDSAVerifyBatch(messages, signatures, pubkeys, results *UntypedTensor) error {
	return capi.ECDSAVerifyBatch(o.session, getCAPITensor(messages), getCAPITensor(signatures), getCAPITensor(pubkeys), getCAPITensor(results))
}

func (o *cgoCryptoOps) Ed25519VerifyBatch(messages, signatures, pubkeys, results *UntypedTensor) error {
	return capi.Ed25519VerifyBatch(o.session, getCAPITensor(messages), getCAPITensor(signatures), getCAPITensor(pubkeys), getCAPITensor(results))
}

func (o *cgoCryptoOps) BLSVerifyBatch(messages, signatures, pubkeys, results *UntypedTensor) error {
	return capi.BLSVerifyBatch(o.session, getCAPITensor(messages), getCAPITensor(signatures), getCAPITensor(pubkeys), getCAPITensor(results))
}

func (o *cgoCryptoOps) BLSAggregate(signatures, aggregated *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoCryptoOps) MerkleRoot(leaves, root *UntypedTensor) error {
	return capi.MerkleRoot(o.session, getCAPITensor(leaves), getCAPITensor(root))
}

func (o *cgoCryptoOps) MerkleBatch(leavesSet, roots *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoCryptoOps) MerkleProof(leaves *UntypedTensor, leafIndex int, proof *UntypedTensor) error {
	return ErrNotSupported
}

// cgoZKOps implements ZKOps using CGO.
type cgoZKOps struct {
	session *capi.Session
}

func (o *cgoZKOps) NTT(input, output, roots *UntypedTensor, modulus uint64) error {
	return capi.NTT(o.session, getCAPITensor(input), getCAPITensor(output), getCAPITensor(roots), modulus)
}

func (o *cgoZKOps) INTT(input, output, invRoots *UntypedTensor, modulus uint64) error {
	return capi.INTT(o.session, getCAPITensor(input), getCAPITensor(output), getCAPITensor(invRoots), modulus)
}

func (o *cgoZKOps) MSM(scalars, bases, result *UntypedTensor) error {
	return capi.MSM(o.session, getCAPITensor(scalars), getCAPITensor(bases), getCAPITensor(result))
}

func (o *cgoZKOps) MSMBatch(scalars, bases, results *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoZKOps) PolyMul(a, b, c *UntypedTensor, modulus uint64) error {
	return capi.PolyMul(o.session, getCAPITensor(a), getCAPITensor(b), getCAPITensor(c), modulus)
}

func (o *cgoZKOps) PolyEval(coeffs, points, results *UntypedTensor, modulus uint64) error {
	return ErrNotSupported
}

func (o *cgoZKOps) CommitPoly(coeffs, srs, commitment *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoZKOps) FFT(input, output *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoZKOps) IFFT(input, output *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoZKOps) FieldAdd(a, b, c *UntypedTensor, modulus uint64) error {
	return ErrNotSupported
}

func (o *cgoZKOps) FieldMul(a, b, c *UntypedTensor, modulus uint64) error {
	return ErrNotSupported
}

func (o *cgoZKOps) FieldInv(a, b *UntypedTensor, modulus uint64) error {
	return ErrNotSupported
}

// cgoLatticeOps implements LatticeOps using CGO.
type cgoLatticeOps struct {
	session *capi.Session
}

func (o *cgoLatticeOps) KyberKeyGen(pk, sk *UntypedTensor) error {
	return capi.KyberKeyGen(o.session, getCAPITensor(pk), getCAPITensor(sk))
}

func (o *cgoLatticeOps) KyberKeyGenBatch(pk, sk *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoLatticeOps) KyberEncaps(pk, ct, ss *UntypedTensor) error {
	return capi.KyberEncaps(o.session, getCAPITensor(pk), getCAPITensor(ct), getCAPITensor(ss))
}

func (o *cgoLatticeOps) KyberEncapsBatch(pk, ct, ss *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoLatticeOps) KyberDecaps(ct, sk, ss *UntypedTensor) error {
	return capi.KyberDecaps(o.session, getCAPITensor(ct), getCAPITensor(sk), getCAPITensor(ss))
}

func (o *cgoLatticeOps) KyberDecapsBatch(ct, sk, ss *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoLatticeOps) DilithiumKeyGen(pk, sk *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoLatticeOps) DilithiumSign(msg, sk, sig *UntypedTensor) error {
	return capi.DilithiumSign(o.session, getCAPITensor(msg), getCAPITensor(sk), getCAPITensor(sig))
}

func (o *cgoLatticeOps) DilithiumSignBatch(msgs, sk, sigs *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoLatticeOps) DilithiumVerify(msg, sig, pk *UntypedTensor) (bool, error) {
	return capi.DilithiumVerify(o.session, getCAPITensor(msg), getCAPITensor(sig), getCAPITensor(pk))
}

func (o *cgoLatticeOps) DilithiumVerifyBatch(msgs, sigs, pks, results *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoLatticeOps) PolynomialNTT(input, output *UntypedTensor, q uint32) error {
	return ErrNotSupported
}

func (o *cgoLatticeOps) PolynomialINTT(input, output *UntypedTensor, q uint32) error {
	return ErrNotSupported
}

func (o *cgoLatticeOps) PolynomialMul(a, b, c *UntypedTensor, q uint32) error {
	return ErrNotSupported
}

func (o *cgoLatticeOps) PolynomialAdd(a, b, c *UntypedTensor, q uint32) error {
	return ErrNotSupported
}

// cgoFHEOps implements FHEOps using CGO.
type cgoFHEOps struct {
	session *capi.Session
}

func (o *cgoFHEOps) BFVEncrypt(plaintext, pk, ciphertext *UntypedTensor) error {
	return capi.BFVEncrypt(o.session, getCAPITensor(plaintext), getCAPITensor(pk), getCAPITensor(ciphertext))
}

func (o *cgoFHEOps) BFVEncryptBatch(plaintexts, pk, ciphertexts *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoFHEOps) BFVDecrypt(ciphertext, sk, plaintext *UntypedTensor) error {
	return capi.BFVDecrypt(o.session, getCAPITensor(ciphertext), getCAPITensor(sk), getCAPITensor(plaintext))
}

func (o *cgoFHEOps) BFVAdd(ct1, ct2, result *UntypedTensor) error {
	return capi.BFVAdd(o.session, getCAPITensor(ct1), getCAPITensor(ct2), getCAPITensor(result))
}

func (o *cgoFHEOps) BFVMultiply(ct1, ct2, relinKey, result *UntypedTensor) error {
	return capi.BFVMultiply(o.session, getCAPITensor(ct1), getCAPITensor(ct2), getCAPITensor(relinKey), getCAPITensor(result))
}

func (o *cgoFHEOps) BFVMultiplyPlain(ct, plain, result *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoFHEOps) BFVRotate(ct, galoisKey *UntypedTensor, steps int, result *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoFHEOps) CKKSEncrypt(plaintext, pk *UntypedTensor, scale float64, ciphertext *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoFHEOps) CKKSDecrypt(ciphertext, sk, plaintext *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoFHEOps) CKKSAdd(ct1, ct2, result *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoFHEOps) CKKSMultiply(ct1, ct2, relinKey, result *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoFHEOps) CKKSRescale(ct, result *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoFHEOps) CKKSRotate(ct, galoisKey *UntypedTensor, steps int, result *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoFHEOps) Bootstrap(ct, bootstrapKey, result *UntypedTensor) error {
	return ErrNotSupported
}

// cgoDEXOps implements DEXOps using CGO.
type cgoDEXOps struct {
	session *capi.Session
}

func (o *cgoDEXOps) ConstantProductSwap(reserveX, reserveY, amountIn *UntypedTensor, xToY bool, amountOut *UntypedTensor, fee float32) error {
	return capi.ConstantProductSwap(o.session, getCAPITensor(reserveX), getCAPITensor(reserveY), getCAPITensor(amountIn), getCAPITensor(amountOut), xToY, fee)
}

func (o *cgoDEXOps) ConstantProductSwapBatch(reserves, swaps, amounts *UntypedTensor, fee float32) error {
	return ErrNotSupported
}

func (o *cgoDEXOps) ComputeTWAP(prices, timestamps *UntypedTensor, start, end uint64, twap *UntypedTensor) error {
	return capi.ComputeTWAP(o.session, getCAPITensor(prices), getCAPITensor(timestamps), getCAPITensor(twap), start, end)
}

func (o *cgoDEXOps) MatchOrders(bids, asks, matches, prices, amounts *UntypedTensor) error {
	return capi.MatchOrders(o.session, getCAPITensor(bids), getCAPITensor(asks), getCAPITensor(matches), getCAPITensor(prices), getCAPITensor(amounts))
}

func (o *cgoDEXOps) MatchOrdersWithPriority(bids, asks, matches *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoDEXOps) ComputeLiquidity(tickLower, tickUpper, amounts, liquidity *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoDEXOps) ComputePositionValue(liquidity, tickLower, tickUpper *UntypedTensor, currentTick int32, values *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoDEXOps) CalculateFees(liquidity, feeGrowthInside0, feeGrowthInside1, fees *UntypedTensor) error {
	return ErrNotSupported
}

func (o *cgoDEXOps) BatchSettlement(trades, balances, newBalances *UntypedTensor) error {
	return ErrNotSupported
}
