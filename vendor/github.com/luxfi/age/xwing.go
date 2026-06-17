// Copyright 2025 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/luxfi/age/internal/bech32"
	"github.com/luxfi/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"crypto/sha256"
	"io"
)

// X-Wing KEM per IETF draft-connolly-cfrg-xwing-kem-10.
//
// This is the REAL X-Wing: a standalone KEM that combines ML-KEM-768
// and X25519 with a SHA3-256 combiner and a fixed 6-byte label.
// It is NOT the same as the HybridRecipient (HPKE MLKEM768X25519).
//
// Sizes per the spec:
//   - Seed (private):     32 bytes
//   - Public key:       1216 bytes (1184 ML-KEM-768 + 32 X25519)
//   - Ciphertext:       1120 bytes (1088 ML-KEM-768 + 32 X25519)
//   - Shared secret:      32 bytes

const (
	xwingSeedSize       = 32
	xwingPublicKeySize  = mlkem.EncapsulationKeySize768 + 32 // 1216
	xwingCiphertextSize = mlkem.CiphertextSize768 + 32       // 1120
	xwingSharedKeySize  = 32

	xwingLabel = "age-encryption.org/v1/xwing"
)

// xwingKEMLabel is the 6-byte combiner label from the spec:
//
//	\./
//	/^\
var xwingKEMLabel = []byte(`\./` + `/^\`)

// XWingRecipient is a post-quantum age public key using the X-Wing KEM
// (IETF draft-connolly-cfrg-xwing-kem-10). Messages encrypted to this
// recipient can be decrypted with the corresponding [XWingIdentity].
//
// X-Wing combines ML-KEM-768 and X25519 in a standalone KEM with a
// SHA3-256 combiner, distinct from the HPKE-based [HybridRecipient].
type XWingRecipient struct {
	pkM []byte // 1184-byte ML-KEM-768 encapsulation key
	pkX []byte // 32-byte X25519 public key
}

var _ Recipient = &XWingRecipient{}

// newXWingRecipient creates an XWingRecipient from the raw 1216-byte public key.
func newXWingRecipient(pk []byte) (*XWingRecipient, error) {
	if len(pk) != xwingPublicKeySize {
		return nil, fmt.Errorf("invalid X-Wing public key: expected %d bytes, got %d", xwingPublicKeySize, len(pk))
	}
	// Validate the ML-KEM-768 portion.
	if _, err := mlkem.NewEncapsulationKey768(pk[:mlkem.EncapsulationKeySize768]); err != nil {
		return nil, fmt.Errorf("invalid X-Wing public key: ML-KEM-768: %v", err)
	}
	r := &XWingRecipient{
		pkM: make([]byte, mlkem.EncapsulationKeySize768),
		pkX: make([]byte, 32),
	}
	copy(r.pkM, pk[:mlkem.EncapsulationKeySize768])
	copy(r.pkX, pk[mlkem.EncapsulationKeySize768:])
	return r, nil
}

// ParseXWingRecipient returns a new [XWingRecipient] from a Bech32 public key
// encoding with the "age1xw1" prefix.
func ParseXWingRecipient(s string) (*XWingRecipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "age1xw" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}
	r, err := newXWingRecipient(k)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	return r, nil
}

func (r *XWingRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	s, _, err := r.WrapWithLabels(fileKey)
	return s, err
}

// WrapWithLabels implements [RecipientWithLabels], returning a single
// "postquantum" label. This ensures an XWingRecipient can be mixed with
// other post-quantum recipients (like HybridRecipient) but not with
// classic X25519 recipients.
func (r *XWingRecipient) WrapWithLabels(fileKey []byte) ([]*Stanza, []string, error) {
	// Encapsulate: produce shared secret and ciphertext.
	ekM, err := mlkem.NewEncapsulationKey768(r.pkM)
	if err != nil {
		return nil, nil, fmt.Errorf("xwing: invalid ML-KEM-768 key: %v", err)
	}
	ssM, ctM := ekM.Encapsulate()

	// X25519 ephemeral key exchange.
	ekX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("xwing: generate X25519 ephemeral: %v", err)
	}
	ctX := ekX.PublicKey().Bytes() // 32-byte ephemeral public key IS the ct_X

	pkXKey, err := ecdh.X25519().NewPublicKey(r.pkX)
	if err != nil {
		return nil, nil, fmt.Errorf("xwing: invalid X25519 public key: %v", err)
	}
	ssX, err := ekX.ECDH(pkXKey)
	if err != nil {
		return nil, nil, fmt.Errorf("xwing: X25519 ECDH: %v", err)
	}

	// Combiner: ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
	ss := xwingCombine(ssM, ssX, ctX, r.pkX)

	// Derive a wrapping key from the shared secret and encrypt the file key.
	wrappingKey := xwingDeriveWrappingKey(ss, ctM, ctX)
	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, nil, fmt.Errorf("xwing: wrap file key: %v", err)
	}

	// Ciphertext = ct_M || ct_X (1088 + 32 = 1120 bytes).
	ct := make([]byte, 0, xwingCiphertextSize)
	ct = append(ct, ctM...)
	ct = append(ct, ctX...)

	l := &Stanza{
		Type: "xwing",
		Args: []string{format.EncodeToString(ct)},
		Body: wrappedKey,
	}
	return []*Stanza{l}, []string{"postquantum"}, nil
}

// String returns the Bech32 public key encoding of r with "age1xw" prefix.
func (r *XWingRecipient) String() string {
	pk := make([]byte, 0, xwingPublicKeySize)
	pk = append(pk, r.pkM...)
	pk = append(pk, r.pkX...)
	s, _ := bech32.Encode("age1xw", pk)
	return s
}

// XWingIdentity is a post-quantum age private key using the X-Wing KEM,
// which can decrypt messages encrypted to the corresponding [XWingRecipient].
type XWingIdentity struct {
	seed [xwingSeedSize]byte
	dkM  *mlkem.DecapsulationKey768
	skX  *ecdh.PrivateKey
	pkX  []byte // cached 32-byte X25519 public key
}

var _ Identity = &XWingIdentity{}

// newXWingIdentity expands a 32-byte seed into an XWingIdentity per the spec.
//
// KeyGen:
//
//	expanded = SHAKE256(seed, 96)
//	(pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:64])
//	sk_X = expanded[64:96]
//	pk_X = X25519(sk_X, basepoint)
func newXWingIdentity(seed []byte) (*XWingIdentity, error) {
	if len(seed) != xwingSeedSize {
		return nil, fmt.Errorf("invalid X-Wing seed: expected %d bytes, got %d", xwingSeedSize, len(seed))
	}

	// SHAKE256(seed, 96)
	h := sha3.NewShake256()
	h.Write(seed)
	var expanded [96]byte
	h.Read(expanded[:])

	// ML-KEM-768 deterministic keygen from d||z (64 bytes).
	dkM, err := mlkem.NewDecapsulationKey768(expanded[:64])
	if err != nil {
		return nil, fmt.Errorf("xwing: ML-KEM-768 keygen: %v", err)
	}

	// X25519 from expanded[64:96].
	skX, err := ecdh.X25519().NewPrivateKey(expanded[64:96])
	if err != nil {
		return nil, fmt.Errorf("xwing: X25519 keygen: %v", err)
	}

	i := &XWingIdentity{
		dkM: dkM,
		skX: skX,
		pkX: skX.PublicKey().Bytes(),
	}
	copy(i.seed[:], seed)
	return i, nil
}

// GenerateXWingIdentity randomly generates a new [XWingIdentity].
func GenerateXWingIdentity() (*XWingIdentity, error) {
	var seed [xwingSeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("xwing: random seed: %v", err)
	}
	return newXWingIdentity(seed[:])
}

// ParseXWingIdentity returns a new [XWingIdentity] from a Bech32 private key
// encoding with the "AGE-SECRET-KEY-XW-1" prefix.
func ParseXWingIdentity(s string) (*XWingIdentity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-SECRET-KEY-XW-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}
	i, err := newXWingIdentity(k)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	return i, nil
}

func (i *XWingIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *XWingIdentity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "xwing" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid xwing recipient block")
	}
	ct, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse xwing recipient: %v", err)
	}
	if len(ct) != xwingCiphertextSize {
		return nil, fmt.Errorf("invalid xwing ciphertext: expected %d bytes, got %d", xwingCiphertextSize, len(ct))
	}
	if len(block.Body) != fileKeySize+chacha20poly1305.Overhead {
		return nil, errIncorrectCiphertextSize
	}

	ctM := ct[:mlkem.CiphertextSize768]
	ctX := ct[mlkem.CiphertextSize768:]

	// ML-KEM-768 decapsulate.
	ssM, err := i.dkM.Decapsulate(ctM)
	if err != nil {
		return nil, fmt.Errorf("xwing: ML-KEM-768 decapsulate: %v", err)
	}

	// X25519 shared secret.
	ctXKey, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, fmt.Errorf("xwing: invalid X25519 ephemeral: %v", err)
	}
	ssX, err := i.skX.ECDH(ctXKey)
	if err != nil {
		return nil, fmt.Errorf("xwing: X25519 ECDH: %v", err)
	}

	// Combiner: ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
	ss := xwingCombine(ssM, ssX, ctX, i.pkX)

	// Derive wrapping key and decrypt file key.
	wrappingKey := xwingDeriveWrappingKey(ss, ctM, ctX)
	fileKey, err := aeadDecrypt(wrappingKey, fileKeySize, block.Body)
	if err == errIncorrectCiphertextSize {
		return nil, errors.New("invalid xwing recipient block: incorrect file key size")
	} else if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}

// Recipient returns the public [XWingRecipient] value corresponding to i.
func (i *XWingIdentity) Recipient() *XWingRecipient {
	return &XWingRecipient{
		pkM: i.dkM.EncapsulationKey().Bytes(),
		pkX: append([]byte(nil), i.pkX...),
	}
}

// String returns the Bech32 private key encoding of i.
func (i *XWingIdentity) String() string {
	s, _ := bech32.Encode("AGE-SECRET-KEY-XW-", i.seed[:])
	return strings.ToUpper(s)
}

// xwingCombine implements the X-Wing combiner:
//
//	ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || "\.\//^\")
func xwingCombine(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
	h.Write(xwingKEMLabel)
	return h.Sum(nil)
}

// xwingDeriveWrappingKey derives a ChaCha20-Poly1305 wrapping key from the
// X-Wing shared secret and ciphertext components, using HKDF-SHA256 for
// domain separation within the age file format.
func xwingDeriveWrappingKey(ss, ctM, ctX []byte) []byte {
	salt := make([]byte, 0, len(ctM)+len(ctX))
	salt = append(salt, ctM...)
	salt = append(salt, ctX...)
	h := hkdf.New(sha256.New, ss, salt, []byte(xwingLabel))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		panic("age: internal error: failed to read from HKDF: " + err.Error())
	}
	return key
}
