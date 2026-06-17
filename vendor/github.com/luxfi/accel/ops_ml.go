package accel

// MLOps provides GPU-accelerated machine learning operations.
type MLOps interface {
	// MatMul performs matrix multiplication: C = A @ B
	MatMul(a, b, c *UntypedTensor) error

	// MatMulTranspose performs C = A @ B^T or C = A^T @ B
	MatMulTranspose(a, b, c *UntypedTensor, transposeA, transposeB bool) error

	// ReLU applies rectified linear unit: y = max(0, x)
	ReLU(input, output *UntypedTensor) error

	// GELU applies Gaussian error linear unit activation
	GELU(input, output *UntypedTensor) error

	// Softmax applies softmax along an axis
	Softmax(input, output *UntypedTensor, axis int) error

	// LayerNorm applies layer normalization
	LayerNorm(input, gamma, beta, output *UntypedTensor, eps float32) error

	// Attention computes scaled dot-product attention
	// output = softmax(Q @ K^T / scale) @ V
	Attention(q, k, v, output *UntypedTensor, scale float32) error

	// Conv2D performs 2D convolution
	Conv2D(input, kernel, output *UntypedTensor, stride, padding [2]int) error

	// MaxPool2D performs 2D max pooling
	MaxPool2D(input, output *UntypedTensor, kernelSize, stride [2]int) error

	// BatchNorm applies batch normalization
	BatchNorm(input, gamma, beta, mean, variance, output *UntypedTensor, eps float32) error

	// Dropout applies dropout with given probability (inference mode)
	Dropout(input, output *UntypedTensor, p float32) error

	// Add performs element-wise addition
	Add(a, b, c *UntypedTensor) error

	// Multiply performs element-wise multiplication
	Multiply(a, b, c *UntypedTensor) error

	// Sum reduces tensor along specified axes
	Sum(input, output *UntypedTensor, axes []int) error

	// Mean reduces tensor along specified axes
	Mean(input, output *UntypedTensor, axes []int) error
}
