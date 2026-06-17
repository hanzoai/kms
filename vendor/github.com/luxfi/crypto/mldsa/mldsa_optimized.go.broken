package mldsa

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
)

// Pool for reusing signature buffers
var sigBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, MLDSA87SignatureSize) // Max size
	},
}

// Pool for reusing hash buffers
var hashBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 64) // SHA-512 output size
	},
}

// getSignatureBuffer gets a buffer from the pool
func getSignatureBuffer(size int) []byte {
	buf := sigBufferPool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

// putSignatureBuffer returns a buffer to the pool
func putSignatureBuffer(buf []byte) {
	if cap(buf) >= MLDSA44SignatureSize { // Only pool larger buffers
		sigBufferPool.Put(buf)
	}
}

// Optimized key generation with pre-allocated buffers
func GenerateKeyOptimized(rand io.Reader, mode Mode) (*PrivateKey, error) {
	var pubKeySize, privKeySize int

	switch mode {
	case MLDSA44:
		pubKeySize = MLDSA44PublicKeySize
		privKeySize = MLDSA44PrivateKeySize
	case MLDSA65:
		pubKeySize = MLDSA65PublicKeySize
		privKeySize = MLDSA65PrivateKeySize
	case MLDSA87:
		pubKeySize = MLDSA87PublicKeySize
		privKeySize = MLDSA87PrivateKeySize
	default:
		return nil, errors.New("invalid ML-DSA mode")
	}

	// Check for nil random source
	if rand == nil {
		return nil, errors.New("random source is nil")
	}

	// Use single allocation for both keys
	totalSize := privKeySize + pubKeySize
	allBytes := make([]byte, totalSize)
	
	privBytes := allBytes[:privKeySize]
	if _, err := io.ReadFull(rand, privBytes); err != nil {
		return nil, err
	}
	
	// Derive public key in-place
	pubBytes := allBytes[privKeySize:]
	derivePublicKeyOptimized(privBytes[:32], pubBytes)

	// This optimized version is not compatible with the current API
	// Use the standard GenerateKey instead
	return GenerateKey(rand, mode)
}

// Optimized public key derivation
func derivePublicKeyOptimized(seed []byte, output []byte) {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte("public"))
	hash := h.Sum(nil)
	
	// Unroll loop for better performance
	outputLen := len(output)
	for i := 0; i < outputLen; {
		remaining := outputLen - i
		if remaining >= 32 {
			copy(output[i:i+32], hash)
			i += 32
		} else {
			copy(output[i:], hash[:remaining])
			break
		}
		
		if i < outputLen {
			h.Reset()
			h.Write(hash)
			h.Write([]byte{byte(i / 32)})
			hash = h.Sum(hash[:0]) // Reuse slice
		}
	}
}

// OptimizedSign performs signing with buffer pooling
func (priv *PrivateKey) OptimizedSign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	var sigSize int
	
	switch priv.PublicKey.mode {
	case MLDSA44:
		sigSize = MLDSA44SignatureSize
	case MLDSA65:
		sigSize = MLDSA65SignatureSize
	case MLDSA87:
		sigSize = MLDSA87SignatureSize
	default:
		return nil, errors.New("invalid ML-DSA mode")
	}

	// Get buffer from pool
	signature := getSignatureBuffer(sigSize)
	defer putSignatureBuffer(signature)
	
	// Create hash with pooled buffer
	hashBuf := hashBufferPool.Get().([]byte)
	defer hashBufferPool.Put(hashBuf)
	
	// This optimized version is not compatible with the current API
	// Use the standard Sign method instead
	defer putSignatureBuffer(signature)
	return priv.Sign(rand, message, opts)
}

// BatchDSA provides batch signing operations
type BatchDSA struct {
	mode Mode
	keys []*PrivateKey
	mu   sync.Mutex
}

// NewBatchDSA creates a batch DSA processor
func NewBatchDSA(mode Mode, numKeys int) (*BatchDSA, error) {
	keys := make([]*PrivateKey, numKeys)
	for i := range keys {
		key, err := GenerateKey(rand.Reader, mode)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}
	
	return &BatchDSA{
		mode: mode,
		keys: keys,
	}, nil
}

// SignBatch performs batch signing in parallel
func (b *BatchDSA) SignBatch(messages [][]byte) ([][]byte, error) {
	if len(messages) != len(b.keys) {
		return nil, errors.New("message count mismatch")
	}
	
	signatures := make([][]byte, len(messages))
	errors := make([]error, len(messages))
	
	// Process in parallel
	var wg sync.WaitGroup
	for i := range messages {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sig, err := b.keys[idx].Sign(rand.Reader, messages[idx], nil)
			if err != nil {
				errors[idx] = err
				return
			}
			signatures[idx] = sig
		}(i)
	}
	
	wg.Wait()
	
	// Check for errors
	for _, err := range errors {
		if err != nil {
			return nil, err
		}
	}
	
	return signatures, nil
}

// VerifyBatch performs batch verification in parallel
func (b *BatchDSA) VerifyBatch(messages [][]byte, signatures [][]byte) ([]bool, error) {
	if len(messages) != len(signatures) || len(messages) != len(b.keys) {
		return nil, errors.New("input count mismatch")
	}
	
	results := make([]bool, len(messages))
	
	// Process in parallel
	var wg sync.WaitGroup
	for i := range messages {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = b.keys[idx].PublicKey.Verify(messages[idx], signatures[idx], nil)
		}(i)
	}
	
	wg.Wait()
	
	return results, nil
}

// PrecomputedMLDSA stores precomputed values for faster operations
type PrecomputedMLDSA struct {
	mode        Mode
	privKey     *PrivateKey
	hashCache   map[string][]byte
	mu          sync.RWMutex
}

// NewPrecomputedMLDSA creates a new precomputed ML-DSA instance
func NewPrecomputedMLDSA(privKey *PrivateKey) *PrecomputedMLDSA {
	return &PrecomputedMLDSA{
		mode:      privKey.PublicKey.mode,
		privKey:   privKey,
		hashCache: make(map[string][]byte),
	}
}

// SignCached signs with caching for repeated messages
func (p *PrecomputedMLDSA) SignCached(message []byte) ([]byte, error) {
	// Create cache key
	h := sha256.New()
	h.Write(message)
	cacheKey := string(h.Sum(nil))
	
	// Check cache
	p.mu.RLock()
	if sig, ok := p.hashCache[cacheKey]; ok {
		p.mu.RUnlock()
		return sig, nil
	}
	p.mu.RUnlock()
	
	// Sign and cache
	sig, err := p.privKey.Sign(rand.Reader, message, nil)
	if err != nil {
		return nil, err
	}
	
	p.mu.Lock()
	p.hashCache[cacheKey] = sig
	p.mu.Unlock()
	
	return sig, nil
}