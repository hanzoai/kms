package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	badger "github.com/luxfi/zapdb"
)

var ErrSecretNotFound = errors.New("store: secret not found")

// Secret storage modes.
const (
	// ModeStandard: AES-256-GCM payload + ML-KEM wrapped DEK.
	// Fast, PQ-safe. No threshold required. Default for all secrets.
	ModeStandard = "aead+mlkem"

	// ModeThresholdReveal: payload or DEK under T-Chain threshold FHE key.
	// Decrypt requires t-of-n validator cooperation via E2S protocol.
	// Use for high-value secrets, sealed recovery, conditional access.
	ModeThresholdReveal = "tfhe"

	// ModeConfidentialCompute: CKKS ciphertext for computation on encrypted data.
	// Use for ML inference on encrypted inputs.
	ModeConfidentialCompute = "ckks"
)

// Key prefix for secrets in ZapDB.
var secretPrefix = []byte("kms/secrets/")

// Secret is an encrypted record stored in ZapDB. Plaintext is never stored.
//
// Standard path (default):
//
//	DEK = random 256-bit key
//	Ciphertext = AES-256-GCM(plaintext, DEK)
//	WrappedDEK = ML-KEM-Encaps(DEK, recipientPK)
//	Policy, handles, receipts anchored on K-Chain
//
// Threshold reveal path (opt-in):
//
//	Ciphertext = TFHE-Encrypt(plaintext, collectivePK)
//	Decrypt requires T-Chain quorum (t-of-n E2S shares)
type Secret struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`        // e.g. "/ci", "/securegate/local"
	Env        string    `json:"env"`         // dev, test, main
	Ciphertext []byte    `json:"ciphertext"`  // AES-GCM ciphertext or TFHE ciphertext
	WrappedDEK []byte    `json:"wrapped_dek"` // ML-KEM encapsulated DEK (standard mode only)
	Scheme     string    `json:"scheme"`      // aead+mlkem (default), tfhe, ckks
	KeyHandle  string    `json:"key_handle"`  // K-Chain key/policy handle
	PolicyID   string    `json:"policy_id"`   // access policy (who can decrypt)
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SecretStore manages encrypted secrets in ZapDB.
type SecretStore struct {
	db *badger.DB
}

// NewSecretStore creates a secret store backed by ZapDB.
func NewSecretStore(db *badger.DB) *SecretStore {
	return &SecretStore{db: db}
}

// secretKey returns the ZapDB key for a secret: kms/secrets/{path}/{env}/{name}
func secretKey(path, name, env string) []byte {
	return []byte(fmt.Sprintf("kms/secrets/%s/%s/%s", path, env, name))
}

// secretListPrefix returns the prefix for listing secrets at a path/env.
func secretListPrefix(path, env string) []byte {
	return []byte(fmt.Sprintf("kms/secrets/%s/%s/", path, env))
}

// Put stores an encrypted secret (upsert).
func (s *SecretStore) Put(secret *Secret) error {
	if secret.Scheme == "" {
		secret.Scheme = ModeStandard
	}
	raw, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(secretKey(secret.Path, secret.Name, secret.Env), raw)
	})
}

// Get retrieves an encrypted secret. Caller must decrypt via appropriate path.
func (s *SecretStore) Get(path, name, env string) (*Secret, error) {
	var secret Secret
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(secretKey(path, name, env))
		if err == badger.ErrKeyNotFound {
			return ErrSecretNotFound
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &secret)
		})
	})
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

// List returns all secrets at a path/env (metadata + ciphertext, no plaintext).
func (s *SecretStore) List(path, env string) ([]*Secret, error) {
	var secrets []*Secret
	prefix := secretListPrefix(path, env)

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var sec Secret
				if err := json.Unmarshal(val, &sec); err != nil {
					return err
				}
				// For listing, strip ciphertext to reduce payload.
				secrets = append(secrets, &Secret{
					Name:      sec.Name,
					Path:      sec.Path,
					Env:       sec.Env,
					Scheme:    sec.Scheme,
					KeyHandle: sec.KeyHandle,
					PolicyID:  sec.PolicyID,
				})
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

// Delete removes a secret.
func (s *SecretStore) Delete(path, name, env string) error {
	key := secretKey(path, name, env)
	return s.db.Update(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			return ErrSecretNotFound
		}
		if err != nil {
			return err
		}
		return txn.Delete(key)
	})
}
