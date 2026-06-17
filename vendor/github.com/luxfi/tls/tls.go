// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	ctls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	readOnlyPerm      = 0o400
	readWriteExecPerm = 0o750
)

// InitNodeStakingKeyPair generates a self-signed TLS key/cert pair to use in
// node staking. The key and files will be placed at [keyPath] and [certPath],
// respectively. If there is already a file at [keyPath], returns nil.
func InitNodeStakingKeyPair(keyPath, certPath string) error {
	// If there is already a file at [keyPath], do nothing
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		return nil
	}

	certBytes, keyBytes, err := NewCertAndKeyBytes()
	if err != nil {
		return err
	}

	// Ensure directory where key/cert will live exist
	if err := os.MkdirAll(filepath.Dir(certPath), readWriteExecPerm); err != nil {
		return fmt.Errorf("couldn't create path for cert: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), readWriteExecPerm); err != nil {
		return fmt.Errorf("couldn't create path for key: %w", err)
	}

	// Write cert to disk
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("couldn't create cert file: %w", err)
	}
	if _, err := certFile.Write(certBytes); err != nil {
		return fmt.Errorf("couldn't write cert file: %w", err)
	}
	if err := certFile.Close(); err != nil {
		return fmt.Errorf("couldn't close cert file: %w", err)
	}
	if err := os.Chmod(certPath, readOnlyPerm); err != nil { // Make cert read-only
		return fmt.Errorf("couldn't change permissions on cert: %w", err)
	}

	// Write key to disk
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("couldn't create key file: %w", err)
	}
	if _, err := keyOut.Write(keyBytes); err != nil {
		return fmt.Errorf("couldn't write private key: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("couldn't close key file: %w", err)
	}
	if err := os.Chmod(keyPath, readOnlyPerm); err != nil { // Make key read-only
		return fmt.Errorf("couldn't change permissions on key: %w", err)
	}
	return nil
}

func LoadTLSCertFromBytes(keyBytes, certBytes []byte) (*ctls.Certificate, error) {
	cert, err := ctls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed creating cert: %w", err)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed parsing cert: %w", err)
	}
	return &cert, nil
}

func LoadTLSCertFromFiles(keyPath, certPath string) (*ctls.Certificate, error) {
	cert, err := ctls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed parsing cert: %w", err)
	}
	return &cert, nil
}

func NewTLSCert() (*ctls.Certificate, error) {
	certBytes, keyBytes, err := NewCertAndKeyBytes()
	if err != nil {
		return nil, err
	}
	cert, err := ctls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	return &cert, err
}

// deterministicReader creates a deterministic random source from a seed.
// This is used to make ECDSA certificate signing deterministic.
// Uses native crypto/hkdf from Go 1.24+ for key derivation.
type deterministicReader struct {
	h      func() hash.Hash
	prk    []byte
	info   string
	offset int
	buf    []byte
}

func newDeterministicReader(seed []byte) *deterministicReader {
	h := sha256.New
	info := "lux-staking-cert-deterministic-rand"
	// Extract PRK from seed using HKDF-Extract
	prk, _ := hkdf.Extract(h, seed, nil)
	return &deterministicReader{
		h:    h,
		prk:  prk,
		info: info,
	}
}

func (d *deterministicReader) Read(p []byte) (int, error) {
	// Use HKDF-Expand to generate deterministic bytes on demand
	// Generate enough bytes to satisfy the request
	needed := len(p)
	for len(d.buf) < needed {
		// Expand more bytes using incrementing counter in info
		chunk, err := hkdf.Expand(d.h, d.prk, d.info+string(rune(d.offset)), 32)
		if err != nil {
			return 0, err
		}
		d.buf = append(d.buf, chunk...)
		d.offset++
	}
	copy(p, d.buf[:needed])
	d.buf = d.buf[needed:]
	return needed, nil
}

// NewCertAndKeyBytesFromKey creates a TLS cert from an existing ECDSA P-256 private key.
// This allows deterministic NodeID generation from a seed.
// IMPORTANT: Uses deterministic signing for reproducible certificates.
func NewCertAndKeyBytesFromKey(key *ecdsa.PrivateKey) ([]byte, []byte, error) {
	// Create self-signed staking cert using the provided key
	// Use fixed times for deterministic certificate generation
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Date(2000, time.January, 0, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, time.January, 0, 0, 0, 0, 0, time.UTC), // Fixed end date for determinism
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Create a deterministic random source from the private key bytes
	// This ensures the same key always produces the same certificate
	randReader := newDeterministicReader(key.D.Bytes())

	certBytes, err := x509.CreateCertificate(randReader, certTemplate, certTemplate, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't create certificate: %w", err)
	}
	var certBuff bytes.Buffer
	if err := pem.Encode(&certBuff, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, nil, fmt.Errorf("couldn't write cert file: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't marshal private key: %w", err)
	}

	var keyBuff bytes.Buffer
	if err := pem.Encode(&keyBuff, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, fmt.Errorf("couldn't write private key: %w", err)
	}
	return certBuff.Bytes(), keyBuff.Bytes(), nil
}

// Creates a new TLS private key / TLS certificate pair.
// Returns the PEM byte representations of both.
func NewCertAndKeyBytes() ([]byte, []byte, error) {
	// Create key to sign cert with
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't generate ecdsa key: %w", err)
	}

	// Create self-signed staking cert
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Date(2000, time.January, 0, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't create certificate: %w", err)
	}
	var certBuff bytes.Buffer
	if err := pem.Encode(&certBuff, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, nil, fmt.Errorf("couldn't write cert file: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't marshal private key: %w", err)
	}

	var keyBuff bytes.Buffer
	if err := pem.Encode(&keyBuff, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, fmt.Errorf("couldn't write private key: %w", err)
	}
	return certBuff.Bytes(), keyBuff.Bytes(), nil
}
