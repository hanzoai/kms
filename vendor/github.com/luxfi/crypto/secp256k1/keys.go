// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/luxfi/cache/lru"
	"github.com/luxfi/crypto/cb58"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
)

const (
	// SignatureLen is the number of bytes in a secp256k1 recoverable signature
	SignatureLen = 65

	// PrivateKeyLen is the number of bytes in a secp256k1 private key
	PrivateKeyLen = 32

	// PublicKeyLen is the number of bytes in a secp256k1 public key
	PublicKeyLen = 33

	PrivateKeyPrefix = "PrivateKey-"
	nullStr          = "null"
)

var (
	ErrInvalidSig              = errors.New("invalid signature")
	errInvalidPrivateKeyLength = fmt.Errorf("private key has unexpected length, expected %d", PrivateKeyLen)
	errInvalidPublicKeyLength  = fmt.Errorf("public key has unexpected length, expected %d", PublicKeyLen)
	errInvalidSigLen           = errors.New("invalid signature length")

	secp256k1N     *big.Int
	secp256k1halfN *big.Int
)

func init() {
	secp256k1N = S256().Params().N
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
}

// PubkeyBytesToAddress converts public key bytes to an address using SHA256 + RIPEMD160
func PubkeyBytesToAddress(pubkey []byte) []byte {
	return hash.PubkeyBytesToAddress(pubkey)
}

// RecoverCache is a cache for recovered public keys
var RecoverCache = lru.NewCache[string, *PublicKey](2048)

// PrivateKey wraps an ecdsa.PrivateKey
type PrivateKey struct {
	sk    *ecdsa.PrivateKey
	bytes []byte
}

// PublicKey wraps an ecdsa.PublicKey
type PublicKey struct {
	pk    *ecdsa.PublicKey
	bytes []byte
}

// NewPrivateKey generates a new private key
func NewPrivateKey() (*PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	bytes := PaddedBigBytes(privKey.D, PrivateKeyLen)
	return &PrivateKey{
		sk:    privKey,
		bytes: bytes,
	}, nil
}

// ToPrivateKey converts bytes to a private key.
// The input bytes are copied — the caller may safely zero the original after this call.
func ToPrivateKey(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeyLen {
		return nil, errInvalidPrivateKeyLength
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = S256()
	priv.D = new(big.Int).SetBytes(b)

	// The priv.D must < N
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, errors.New("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = S256().ScalarBaseMult(b)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}

	// Copy input bytes so callers can safely zero the original.
	keyCopy := make([]byte, PrivateKeyLen)
	copy(keyCopy, b)

	return &PrivateKey{
		sk:    priv,
		bytes: keyCopy,
	}, nil
}

// ToPublicKey converts bytes to a public key
func ToPublicKey(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeyLen {
		return nil, errInvalidPublicKeyLength
	}

	x, y := DecompressPubkey(b)
	if x == nil || y == nil {
		return nil, errors.New("invalid public key")
	}

	pub := &ecdsa.PublicKey{
		Curve: S256(),
		X:     x,
		Y:     y,
	}

	return &PublicKey{
		pk:    pub,
		bytes: b,
	}, nil
}

// Sign signs a message with the private key
func (k *PrivateKey) Sign(msg []byte) ([]byte, error) {
	sig, err := k.SignArray(msg)
	if err != nil {
		return nil, err
	}
	return sig[:], nil
}

// SignArray signs a message and returns a fixed-size array
func (k *PrivateKey) SignArray(msg []byte) ([SignatureLen]byte, error) {
	return k.SignHashArray(hash.ComputeHash256(msg))
}

// SignHash signs a hash with the private key
func (k *PrivateKey) SignHash(hash []byte) ([]byte, error) {
	sig, err := k.SignHashArray(hash)
	if err != nil {
		return nil, err
	}
	return sig[:], nil
}

// SignHashArray signs a hash and returns a fixed-size array
func (k *PrivateKey) SignHashArray(hash []byte) ([SignatureLen]byte, error) {
	sig, err := Sign(hash, k.bytes)
	if err != nil {
		return [SignatureLen]byte{}, err
	}
	var result [SignatureLen]byte
	copy(result[:], sig)
	return result, nil
}

// PublicKey returns the public key
func (k *PrivateKey) PublicKey() *PublicKey {
	pubBytes := CompressPubkey(k.sk.PublicKey.X, k.sk.PublicKey.Y)
	return &PublicKey{
		pk:    &k.sk.PublicKey,
		bytes: pubBytes,
	}
}

// Bytes returns the private key bytes
func (k *PrivateKey) Bytes() []byte {
	return k.bytes
}

// ToECDSA returns the underlying ecdsa.PrivateKey
func (k *PrivateKey) ToECDSA() *ecdsa.PrivateKey {
	return k.sk
}

// Address returns the address of the private key (via its public key)
func (k *PrivateKey) Address() ids.ShortID {
	return k.PublicKey().Address()
}

// EthAddress returns the Ethereum address derived from the private key
func (k *PrivateKey) EthAddress() [20]byte {
	return k.PublicKey().EthAddress()
}

// Address returns the address of the public key as an ids.ShortID
func (k *PublicKey) Address() ids.ShortID {
	// Use traditional Lux address format (SHA256 + RIPEMD160)
	// This is used for X-Chain and P-Chain addresses
	compressedBytes := k.CompressedBytes()
	addrBytes := PubkeyBytesToAddress(compressedBytes)
	addr, _ := ids.ToShortID(addrBytes)
	return addr
}

// EthAddress returns the Ethereum address derived from the public key
// This is computed as the last 20 bytes of the Keccak256 hash of the uncompressed public key
func (k *PublicKey) EthAddress() [20]byte {
	// Get uncompressed public key bytes (excluding the 0x04 prefix)
	pkBytes := k.Bytes()

	// Compute Keccak256 hash
	hash := Keccak256(pkBytes)

	// Take the last 20 bytes as the address
	var addr [20]byte
	copy(addr[:], hash[12:])
	return addr
}

// Bytes returns the public key bytes
func (k *PublicKey) Bytes() []byte {
	return k.bytes
}

// CompressedBytes returns the compressed public key bytes (33 bytes)
func (k *PublicKey) CompressedBytes() []byte {
	return CompressPubkey(k.pk.X, k.pk.Y)
}

// ToECDSA returns the underlying ECDSA public key
func (k *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return k.pk
}

// VerifyHash verifies a signature against a hash
func (k *PublicKey) VerifyHash(hash, sig []byte) bool {
	if len(sig) != SignatureLen {
		return false
	}
	return VerifySignature(k.bytes, hash, sig[:64])
}

// Verify verifies a signature against a message
func (k *PublicKey) Verify(msg, sig []byte) bool {
	return k.VerifyHash(hash.ComputeHash256(msg), sig)
}

// RecoverPublicKey recovers the public key from a message and signature
func RecoverPublicKey(msg, sig []byte) (*PublicKey, error) {
	return RecoverPublicKeyFromHash(hash.ComputeHash256(msg), sig)
}

// RecoverPublicKeyFromHash recovers the public key from a hash and signature
func RecoverPublicKeyFromHash(hash, sig []byte) (*PublicKey, error) {
	if len(sig) != SignatureLen {
		return nil, errInvalidSigLen
	}

	// Check cache first
	cacheKey := string(hash) + string(sig)
	if cached, found := RecoverCache.Get(cacheKey); found {
		return cached, nil
	}

	pubBytes, err := RecoverPubkey(hash, sig)
	if err != nil {
		return nil, err
	}

	// RecoverPubkey returns 65-byte uncompressed public key
	// Format: 0x04 + 32-byte X + 32-byte Y
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return nil, errors.New("invalid recovered public key format")
	}

	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])

	pub := &ecdsa.PublicKey{
		Curve: S256(),
		X:     x,
		Y:     y,
	}

	result := &PublicKey{
		pk:    pub,
		bytes: CompressPubkey(x, y), // Store compressed format
	}

	RecoverCache.Put(cacheKey, result)
	return result, nil
}

// MarshalText implements encoding.TextMarshaler
func (k *PrivateKey) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// UnmarshalJSON implements json.Unmarshaler
// It handles JSON-encoded strings by stripping quotes and calling the shared unmarshal logic
func (k *PrivateKey) UnmarshalJSON(data []byte) error {
	str := string(data)
	// JSON strings are always quoted
	if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
		str = str[1 : len(str)-1]
	}
	return k.unmarshalText(str)
}

// UnmarshalText implements encoding.TextUnmarshaler
// It handles direct text unmarshaling without quotes
func (k *PrivateKey) UnmarshalText(text []byte) error {
	return k.unmarshalText(string(text))
}

// unmarshalText is the shared unmarshaling implementation
func (k *PrivateKey) unmarshalText(str string) error {
	if str == nullStr {
		return nil
	}

	// Check and remove prefix
	if !strings.HasPrefix(str, PrivateKeyPrefix) {
		return fmt.Errorf("private key missing %s prefix", PrivateKeyPrefix)
	}
	str = str[len(PrivateKeyPrefix):]

	// Decode from CB58
	bytes, err := cb58.Decode(str)
	if err != nil {
		return err
	}

	// Convert to private key
	priv, err := ToPrivateKey(bytes)
	if err != nil {
		return err
	}

	*k = *priv
	return nil
}

// String returns the string representation of the private key
func (k *PrivateKey) String() string {
	if k == nil || k.sk == nil {
		return nullStr
	}
	encoded, _ := cb58.Encode(k.bytes)
	return PrivateKeyPrefix + encoded
}

// String returns the string representation of the public key
func (k *PublicKey) String() string {
	if k == nil || k.pk == nil {
		return nullStr
	}
	encoded, _ := cb58.Encode(k.bytes)
	return encoded
}

// PaddedBigBytes encodes a big integer as a big-endian byte slice. The byte slice is padded with zeros.
func PaddedBigBytes(bigint *big.Int, n int) []byte {
	if bigint.BitLen()/8 >= n {
		return bigint.Bytes()
	}
	ret := make([]byte, n)
	bigint.FillBytes(ret)
	return ret
}
