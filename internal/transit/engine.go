// Package transit implements a transit encryption engine (Encryption as a Service).
// Key types: AES-256-GCM for symmetric encryption, Ed25519 for signing.
// All crypto uses Go stdlib only.
package transit

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/hanzoai/kms/internal/store"
)

const (
	KeyTypeAES256GCM = "aes-256-gcm"
	KeyTypeEd25519   = "ed25519"
)

var (
	ErrUnknownKeyType = errors.New("transit: unknown key type")
	ErrKeyNotFound    = errors.New("transit: key not found")
)

// KeyStore is the interface the transit engine uses to persist key rings.
type KeyStore interface {
	Create(k *store.TransitKeyRecord) error
	Get(name string) (*store.TransitKeyRecord, error)
	Update(k *store.TransitKeyRecord) error
	List() ([]*store.TransitKeyRecord, error)
	Delete(name string) error
}

// Engine manages transit key rings.
type Engine struct {
	store KeyStore
}

// NewEngine creates a transit engine backed by the given store.
func NewEngine(s KeyStore) *Engine {
	return &Engine{store: s}
}

// CreateKeyRequest is the input for creating a new transit key.
type CreateKeyRequest struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // "aes-256-gcm" or "ed25519"
	Exportable bool   `json:"exportable"`
}

// CreateKey creates a new transit key with version 1.
func (e *Engine) CreateKey(req CreateKeyRequest) error {
	switch req.Type {
	case KeyTypeAES256GCM:
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("transit: generate aes key: %w", err)
		}
		ring, err := store.MarshalKeyRing(map[int][]byte{1: key})
		if err != nil {
			return err
		}
		return e.store.Create(&store.TransitKeyRecord{
			Name:          req.Name,
			KeyType:       req.Type,
			LatestVersion: 1,
			KeyRing:       ring,
			Exportable:    req.Exportable,
		})

	case KeyTypeEd25519:
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return fmt.Errorf("transit: generate ed25519 seed: %w", err)
		}
		ring, err := store.MarshalKeyRing(map[int][]byte{1: seed})
		if err != nil {
			return err
		}
		return e.store.Create(&store.TransitKeyRecord{
			Name:          req.Name,
			KeyType:       req.Type,
			LatestVersion: 1,
			KeyRing:       ring,
			Exportable:    req.Exportable,
		})

	default:
		return ErrUnknownKeyType
	}
}

// GetKeyRing returns the key ring for a named key.
func (e *Engine) GetKeyRing(name string) (*store.TransitKeyRecord, map[int][]byte, error) {
	rec, err := e.store.Get(name)
	if err != nil {
		return nil, nil, ErrKeyNotFound
	}
	ring, err := store.UnmarshalKeyRing(rec.KeyRing)
	if err != nil {
		return nil, nil, fmt.Errorf("transit: decode ring: %w", err)
	}
	return rec, ring, nil
}

// RotateKey adds a new version to the key ring.
func (e *Engine) RotateKey(name string) error {
	rec, ring, err := e.GetKeyRing(name)
	if err != nil {
		return err
	}

	newVersion := rec.LatestVersion + 1
	var keyMaterial []byte

	switch rec.KeyType {
	case KeyTypeAES256GCM:
		keyMaterial = make([]byte, 32)
	case KeyTypeEd25519:
		keyMaterial = make([]byte, 32)
	default:
		return ErrUnknownKeyType
	}

	if _, err := rand.Read(keyMaterial); err != nil {
		return fmt.Errorf("transit: generate key v%d: %w", newVersion, err)
	}

	ring[newVersion] = keyMaterial
	ringStr, err := store.MarshalKeyRing(ring)
	if err != nil {
		return err
	}

	rec.LatestVersion = newVersion
	rec.KeyRing = ringStr
	return e.store.Update(rec)
}
