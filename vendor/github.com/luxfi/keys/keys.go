// Copyright (C) 2024-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package keys provides validator key management for Lux networks.
// It handles generation, loading, and storage of:
// - TLS staking keys (for node identity)
// - BLS signer keys (for validator consensus)
// - EC private keys (for P/X/C-chain addresses)
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/luxfi/crypto/bls/signer/localsigner"
	luxcrypto "github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/go-bip32"
	"github.com/luxfi/go-bip39"
	"github.com/luxfi/ids"
	"github.com/luxfi/proto/p/signer"
	luxtls "github.com/luxfi/tls"
	"golang.org/x/crypto/sha3"
)

// ValidatorKey contains all keys needed for a validator node
type ValidatorKey struct {
	// NodeID is the unique identifier for the node (derived from TLS cert)
	NodeID ids.NodeID

	// TLS keys for node identity
	StakerKey  []byte // PEM-encoded private key
	StakerCert []byte // PEM-encoded certificate

	// BLS keys for consensus
	BLSSecretKey []byte // Raw BLS secret key bytes
	BLSPublicKey []byte // Compressed BLS public key
	BLSPoP       []byte // Proof of Possession signature

	// EC key for addresses
	ECPrivateKey []byte // Raw 32-byte secp256k1 private key

	// Derived addresses
	PChainAddr ids.ShortID // P/X chain address (20 bytes)
	CChainAddr ids.ShortID // C-chain address (20 bytes, Ethereum format)
}

// KeyStore manages validator keys with filesystem persistence
type KeyStore struct {
	baseDir string
}

// NewKeyStore creates a new key store at the given directory
func NewKeyStore(baseDir string) *KeyStore {
	if baseDir == "" {
		home, _ := os.UserHomeDir()
		baseDir = filepath.Join(home, ".lux", "keys")
	}
	return &KeyStore{baseDir: baseDir}
}

// BaseDir returns the base directory for the key store
func (ks *KeyStore) BaseDir() string {
	return ks.baseDir
}

// GenerateValidatorKey creates a complete set of validator keys
func GenerateValidatorKey() (*ValidatorKey, error) {
	vk := &ValidatorKey{}

	// 1. Generate TLS staking key
	certPEM, keyPEM, err := luxtls.NewCertAndKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS cert: %w", err)
	}

	vk.StakerCert = certPEM
	vk.StakerKey = keyPEM

	// Parse cert to derive NodeID
	tlsCert, err := luxtls.LoadTLSCertFromBytes(keyPEM, certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS cert: %w", err)
	}
	stakingCert := &ids.Certificate{
		Raw:       tlsCert.Leaf.Raw,
		PublicKey: tlsCert.Leaf.PublicKey,
	}
	vk.NodeID = ids.NodeIDFromCert(stakingCert)

	// 2. Generate BLS signer key
	blsKey, err := localsigner.New()
	if err != nil {
		return nil, fmt.Errorf("failed to generate BLS key: %w", err)
	}
	vk.BLSSecretKey = blsKey.ToBytes()

	pop, err := signer.NewProofOfPossession(blsKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate BLS PoP: %w", err)
	}
	vk.BLSPublicKey = pop.PublicKey[:]
	vk.BLSPoP = pop.ProofOfPossession[:]

	// 3. Generate EC private key for addresses
	ecKey, err := luxcrypto.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC key: %w", err)
	}
	vk.ECPrivateKey = ecKey.Bytes()

	// Derive P-chain address
	pubKey := ecKey.PublicKey()
	vk.PChainAddr = ids.ShortID(pubKey.Address())

	// Derive C-chain (Ethereum) address
	ecdsaPubKey := pubKey.ToECDSA()
	vk.CChainAddr = pubkeyToAddress(ecdsaPubKey)

	return vk, nil
}

// pubkeyToAddress derives an Ethereum address from an ECDSA public key
func pubkeyToAddress(pub *ecdsa.PublicKey) ids.ShortID {
	// Ethereum address is last 20 bytes of Keccak256(uncompressed pubkey without prefix)
	pubBytes := make([]byte, 64)
	copy(pubBytes[:32], pub.X.Bytes())
	copy(pubBytes[32:], pub.Y.Bytes())

	h := sha3.NewLegacyKeccak256()
	h.Write(pubBytes)
	hash := h.Sum(nil)

	var addr ids.ShortID
	copy(addr[:], hash[12:32])
	return addr
}

// Save persists a validator key to the filesystem
func (ks *KeyStore) Save(name string, vk *ValidatorKey) error {
	nodeDir := filepath.Join(ks.baseDir, name)

	// Create directory structure
	dirs := []string{
		nodeDir,
		filepath.Join(nodeDir, "staking"),
		filepath.Join(nodeDir, "bls"),
		filepath.Join(nodeDir, "ec"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Save TLS staking key and cert
	if err := os.WriteFile(filepath.Join(nodeDir, "staking", "staker.key"), vk.StakerKey, 0600); err != nil {
		return fmt.Errorf("failed to write staker.key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "staking", "staker.crt"), vk.StakerCert, 0644); err != nil {
		return fmt.Errorf("failed to write staker.crt: %w", err)
	}

	// Also save to legacy paths for backward compatibility
	if err := os.WriteFile(filepath.Join(nodeDir, "staker.key"), vk.StakerKey, 0600); err != nil {
		return fmt.Errorf("failed to write staker.key (legacy): %w", err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "staker.crt"), vk.StakerCert, 0644); err != nil {
		return fmt.Errorf("failed to write staker.crt (legacy): %w", err)
	}

	// Save BLS signer key
	if err := os.WriteFile(filepath.Join(nodeDir, "bls", "signer.key"), vk.BLSSecretKey, 0600); err != nil {
		return fmt.Errorf("failed to write signer.key: %w", err)
	}

	// Save EC private key (hex encoded)
	ecKeyHex := hex.EncodeToString(vk.ECPrivateKey)
	if err := os.WriteFile(filepath.Join(nodeDir, "ec", "private.key"), []byte(ecKeyHex), 0600); err != nil {
		return fmt.Errorf("failed to write private.key: %w", err)
	}

	// Save key info JSON for reference
	info := fmt.Sprintf(`{
  "nodeID": "%s",
  "pChainAddr": "%s",
  "cChainAddr": "0x%s",
  "blsPublicKey": "0x%s"
}
`, vk.NodeID.String(),
		vk.PChainAddr.String(),
		hex.EncodeToString(vk.CChainAddr[:]),
		hex.EncodeToString(vk.BLSPublicKey))
	if err := os.WriteFile(filepath.Join(nodeDir, "info.json"), []byte(info), 0644); err != nil {
		return fmt.Errorf("failed to write info.json: %w", err)
	}

	return nil
}

// Load reads a validator key from the filesystem
func (ks *KeyStore) Load(name string) (*ValidatorKey, error) {
	nodeDir := filepath.Join(ks.baseDir, name)
	return LoadFromDir(nodeDir)
}

// LoadFromDir loads a validator key from a specific directory
func LoadFromDir(nodeDir string) (*ValidatorKey, error) {
	vk := &ValidatorKey{}

	// Load TLS cert - try modern path first, then legacy
	certPath := filepath.Join(nodeDir, "staking", "staker.crt")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		certPath = filepath.Join(nodeDir, "staker.crt")
		certPEM, err = os.ReadFile(certPath)
	}

	// Load TLS key
	keyPath := filepath.Join(nodeDir, "staking", "staker.key")
	keyPEM, kerr := os.ReadFile(keyPath)
	if kerr != nil {
		keyPath = filepath.Join(nodeDir, "staker.key")
		keyPEM, kerr = os.ReadFile(keyPath)
	}

	// If TLS cert/key missing, generate them and persist
	if err != nil || kerr != nil || len(certPEM) == 0 || len(keyPEM) == 0 {
		fmt.Printf("  Generating TLS staking cert for %s\n", filepath.Base(nodeDir))
		certPEM, keyPEM, err = luxtls.NewCertAndKeyBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to generate TLS cert: %w", err)
		}
		// Save to disk for future use
		stakingDir := filepath.Join(nodeDir, "staking")
		if err := os.MkdirAll(stakingDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create staking dir: %w", err)
		}
		if err := os.WriteFile(filepath.Join(stakingDir, "staker.key"), keyPEM, 0600); err != nil {
			return nil, fmt.Errorf("failed to write staker.key: %w", err)
		}
		if err := os.WriteFile(filepath.Join(stakingDir, "staker.crt"), certPEM, 0644); err != nil {
			return nil, fmt.Errorf("failed to write staker.crt: %w", err)
		}
	}
	vk.StakerCert = certPEM
	vk.StakerKey = keyPEM

	// Derive NodeID from TLS cert
	tlsCert, err := luxtls.LoadTLSCertFromBytes(keyPEM, certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS cert: %w", err)
	}
	stakingCert := &ids.Certificate{
		Raw:       tlsCert.Leaf.Raw,
		PublicKey: tlsCert.Leaf.PublicKey,
	}
	vk.NodeID = ids.NodeIDFromCert(stakingCert)

	// Load BLS signer key (optional)
	signerPath := filepath.Join(nodeDir, "bls", "signer.key")
	signerBytes, err := os.ReadFile(signerPath)
	if err != nil {
		signerPath = filepath.Join(nodeDir, "signer.key")
		signerBytes, _ = os.ReadFile(signerPath)
	}
	if len(signerBytes) > 0 {
		vk.BLSSecretKey = signerBytes
		// Derive public key and PoP using localsigner + signer.NewProofOfPossession
		// This must match how keys are generated in GenerateValidatorKey/DeriveValidatorFromMnemonic
		blsSigner, err := localsigner.FromBytes(signerBytes)
		if err == nil {
			pop, err := signer.NewProofOfPossession(blsSigner)
			if err == nil {
				vk.BLSPublicKey = pop.PublicKey[:]
				vk.BLSPoP = pop.ProofOfPossession[:]
			}
		}
	}

	// Load EC private key (optional)
	ecPath := filepath.Join(nodeDir, "ec", "private.key")
	ecKeyHex, err := os.ReadFile(ecPath)
	if err != nil {
		ecPath = filepath.Join(nodeDir, "private.key")
		ecKeyHex, _ = os.ReadFile(ecPath)
	}
	if len(ecKeyHex) > 0 {
		privKeyBytes, err := hex.DecodeString(strings.TrimSpace(string(ecKeyHex)))
		if err == nil && len(privKeyBytes) == 32 {
			vk.ECPrivateKey = privKeyBytes

			// Derive addresses
			luxPrivKey, err := luxcrypto.ToPrivateKey(privKeyBytes)
			if err == nil {
				pubKey := luxPrivKey.PublicKey()
				vk.PChainAddr = ids.ShortID(pubKey.Address())
				vk.CChainAddr = pubkeyToAddress(pubKey.ToECDSA())
			}
		}
	}

	// Fallback: derive addresses from NodeID if EC key not available
	if vk.PChainAddr == (ids.ShortID{}) {
		copy(vk.PChainAddr[:], vk.NodeID[:20])
		copy(vk.CChainAddr[:], vk.NodeID[:20])
	}

	return vk, nil
}

// List returns all validator keys in the store
func (ks *KeyStore) List() ([]string, error) {
	entries, err := os.ReadDir(ks.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			name := entry.Name()
			// Skip hidden directories (like .git) and non-node directories
			if strings.HasPrefix(name, ".") {
				continue
			}
			// Only include node* directories
			if !strings.HasPrefix(name, "node") {
				continue
			}
			names = append(names, name)
		}
	}
	return names, nil
}

// GenerateMultiple generates multiple validator keys
func (ks *KeyStore) GenerateMultiple(count int, prefix string) ([]*ValidatorKey, error) {
	keys := make([]*ValidatorKey, count)
	for i := 0; i < count; i++ {
		vk, err := GenerateValidatorKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key %d: %w", i, err)
		}
		keys[i] = vk

		name := fmt.Sprintf("%s%d", prefix, i+1)
		if err := ks.Save(name, vk); err != nil {
			return nil, fmt.Errorf("failed to save key %s: %w", name, err)
		}
	}
	return keys, nil
}

// LoadAll loads all validator keys from the store
func (ks *KeyStore) LoadAll() ([]*ValidatorKey, error) {
	names, err := ks.List()
	if err != nil {
		return nil, err
	}

	keys := make([]*ValidatorKey, 0, len(names))
	for _, name := range names {
		vk, err := ks.Load(name)
		if err != nil {
			continue // Skip invalid entries
		}
		keys = append(keys, vk)
	}
	return keys, nil
}

// BLSKeyBase64 returns the BLS secret key as base64 (for node config)
func (vk *ValidatorKey) BLSKeyBase64() string {
	return base64.StdEncoding.EncodeToString(vk.BLSSecretKey)
}

// BLSPublicKeyHex returns the BLS public key as hex with 0x prefix
func (vk *ValidatorKey) BLSPublicKeyHex() string {
	return "0x" + hex.EncodeToString(vk.BLSPublicKey)
}

// BLSPoPHex returns the BLS proof of possession as hex with 0x prefix
func (vk *ValidatorKey) BLSPoPHex() string {
	return "0x" + hex.EncodeToString(vk.BLSPoP)
}

// CChainAddrHex returns the C-chain address as hex with 0x prefix
func (vk *ValidatorKey) CChainAddrHex() string {
	return "0x" + hex.EncodeToString(vk.CChainAddr[:])
}

// DeriveValidatorsFromMnemonic derives N validator keys from a BIP39 mnemonic.
// Each validator uses BIP44 path m/44'/60'/0'/0/{index} for the EC key.
// TLS staking certs and BLS keys are generated fresh (not deterministic from mnemonic).
// This is designed for runtime use - no files are written to disk.
func DeriveValidatorsFromMnemonic(mnemonic string, count int) ([]*ValidatorKey, error) {
	if count <= 0 || count > 100 {
		return nil, fmt.Errorf("invalid validator count: %d (must be 1-100)", count)
	}

	validators := make([]*ValidatorKey, count)

	for i := 0; i < count; i++ {
		vk, err := DeriveValidatorFromMnemonic(mnemonic, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("failed to derive validator %d: %w", i, err)
		}
		validators[i] = vk
	}

	return validators, nil
}

// DeriveValidatorFromMnemonic derives a single validator key from mnemonic at given index.
// All keys (EC, TLS, BLS) are now derived deterministically from the mnemonic.
func DeriveValidatorFromMnemonic(mnemonic string, accountIndex uint32) (*ValidatorKey, error) {
	vk := &ValidatorKey{}

	// 1. Derive EC key from mnemonic using BIP44 path m/44'/60'/0'/0/{index}
	ecKeyBytes, err := deriveMnemonicKey(mnemonic, accountIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive EC key: %w", err)
	}
	vk.ECPrivateKey = ecKeyBytes

	// Derive P-chain and C-chain addresses
	luxPrivKey, err := luxcrypto.ToPrivateKey(ecKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create secp256k1 key: %w", err)
	}
	pubKey := luxPrivKey.PublicKey()
	vk.PChainAddr = ids.ShortID(pubKey.Address())
	vk.CChainAddr = pubkeyToAddress(pubKey.ToECDSA())

	// 2. Derive TLS staking cert deterministically from mnemonic
	// Use a separate derivation path: m/44'/60'/1'/0/{index} for TLS keys
	tlsKeyBytes, err := deriveMnemonicKeyForPath(mnemonic, 1, accountIndex) // account=1 for TLS
	if err != nil {
		return nil, fmt.Errorf("failed to derive TLS key seed: %w", err)
	}

	// Create P-256 private key from derived seed (TLS uses P-256, not secp256k1)
	p256Key, err := deriveP256Key(tlsKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive P-256 key: %w", err)
	}

	certPEM, keyPEM, err := luxtls.NewCertAndKeyBytesFromKey(p256Key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS cert: %w", err)
	}
	vk.StakerCert = certPEM
	vk.StakerKey = keyPEM

	// Derive NodeID from TLS cert
	tlsCert, err := luxtls.LoadTLSCertFromBytes(keyPEM, certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS cert: %w", err)
	}
	stakingCert := &ids.Certificate{
		Raw:       tlsCert.Leaf.Raw,
		PublicKey: tlsCert.Leaf.PublicKey,
	}
	vk.NodeID = ids.NodeIDFromCert(stakingCert)

	// 3. Derive BLS signer key deterministically from mnemonic
	// Use a separate derivation path: m/44'/60'/2'/0/{index} for BLS keys
	blsSeed, err := deriveMnemonicKeyForPath(mnemonic, 2, accountIndex) // account=2 for BLS
	if err != nil {
		return nil, fmt.Errorf("failed to derive BLS key seed: %w", err)
	}

	// Create BLS signer from seed using proper BLS key derivation (handles field order internally)
	blsKey, err := localsigner.FromSeed(blsSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to create BLS key from seed: %w", err)
	}
	vk.BLSSecretKey = blsKey.ToBytes()

	pop, err := signer.NewProofOfPossession(blsKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate BLS PoP: %w", err)
	}
	vk.BLSPublicKey = pop.PublicKey[:]
	vk.BLSPoP = pop.ProofOfPossession[:]

	return vk, nil
}

// deriveP256Key creates an ECDSA P-256 private key from a 32-byte seed.
// This allows deterministic TLS key generation from mnemonic-derived seeds.
func deriveP256Key(seed []byte) (*ecdsa.PrivateKey, error) {
	if len(seed) < 32 {
		return nil, fmt.Errorf("seed must be at least 32 bytes")
	}

	// Use the seed as the private key scalar (reduced mod curve order)
	curve := elliptic.P256()
	k := new(big.Int).SetBytes(seed[:32])
	k.Mod(k, curve.Params().N)

	// Ensure k is not zero
	if k.Sign() == 0 {
		k.SetInt64(1)
	}

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: k,
	}
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(k.Bytes())

	return priv, nil
}

// deriveMnemonicKeyForPath derives a key using BIP44 path m/44'/60'/{account}'/0/{index}
func deriveMnemonicKeyForPath(mnemonic string, account, index uint32) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}
	seed := bip39.NewSeed(mnemonic, "")

	// Create master key from seed
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// BIP-44 path: m/44'/60'/{account}'/0/{index}
	// m/44' (purpose)
	key, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
	if err != nil {
		return nil, fmt.Errorf("failed to derive purpose: %w", err)
	}

	// m/44'/60' (coin type for LUX)
	key, err = key.NewChildKey(bip32.FirstHardenedChild + CoinTypeEVM)
	if err != nil {
		return nil, fmt.Errorf("failed to derive coin type: %w", err)
	}

	// m/44'/60'/{account}' (account - 0=EC, 1=TLS, 2=BLS)
	key, err = key.NewChildKey(bip32.FirstHardenedChild + account)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account: %w", err)
	}

	// m/44'/60'/{account}'/0 (change)
	key, err = key.NewChildKey(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive change: %w", err)
	}

	// m/44'/60'/{account}'/0/{index} (address index)
	key, err = key.NewChildKey(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address index: %w", err)
	}

	return key.Key, nil
}

// CoinTypeEVM is the SLIP-0044 coin_type for EVM chains (60', shared with
// Ethereum). C-Chain and any non-Lux L1 EVM derive under this tree.
const CoinTypeEVM = 60

// deriveMnemonicKey derives an EC private key from mnemonic using BIP44 path m/44'/60'/0'/0/{index}
func deriveMnemonicKey(mnemonic string, accountIndex uint32) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}
	seed := bip39.NewSeed(mnemonic, "")

	// Create master key from seed
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// BIP-44 path: m/44'/60'/0'/0/{accountIndex}
	// m/44' (purpose)
	key, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
	if err != nil {
		return nil, fmt.Errorf("failed to derive purpose: %w", err)
	}

	// m/44'/60' (coin type for LUX)
	key, err = key.NewChildKey(bip32.FirstHardenedChild + CoinTypeEVM)
	if err != nil {
		return nil, fmt.Errorf("failed to derive coin type: %w", err)
	}

	// m/44'/60'/0' (account)
	key, err = key.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account: %w", err)
	}

	// m/44'/60'/0'/0 (change)
	key, err = key.NewChildKey(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive change: %w", err)
	}

	// m/44'/60'/0'/0/{accountIndex} (address index)
	key, err = key.NewChildKey(accountIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address index: %w", err)
	}

	return key.Key, nil
}
