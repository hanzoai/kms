// Package kms — canonical client interface for Hanzo KMS.
//
//	import kms "github.com/hanzoai/kms/sdk/go"
//	var v kms.Vault = kms.NewClient(cfg)

package kms

import (
	"context"
	"time"
)

// Vault is the secrets-storage surface. Namespaced at construction;
// every method takes leaf names. Goroutine-safe.
type Vault interface {
	// Kind reports the backend identifier
	// (hanzo-kms | aws-secrets-manager | hashicorp-vault | doppler | env).
	Kind() string

	// Get returns the secret value. Empty + non-nil error on missing.
	// Empty + nil is never returned — the contract is "configured xor error".
	Get(ctx context.Context, name string) (string, error)

	// GetWithMeta is Get plus the metadata sidecar.
	GetWithMeta(ctx context.Context, name string) (string, SecretMeta, error)

	// Put writes a new version. Returns the version id if the backend
	// versions; empty string otherwise.
	Put(ctx context.Context, name, value string) (string, error)

	// Rotate generates new material and stores it atomically. `kind` is
	// the generator selector (api_key | webhook_secret | dsn_password |
	// jwt_signing_key). Backends without managed rotation return
	// ErrRotateUnsupported.
	Rotate(ctx context.Context, name, kind string) (newValue, version string, err error)

	// List returns every leaf name in the namespace.
	List(ctx context.Context) ([]string, error)
}

// SecretMeta is the sidecar returned by GetWithMeta.
type SecretMeta struct {
	Name      string
	Version   string
	CreatedAt time.Time
	UpdatedAt time.Time
	// Tags is the backend-attached metadata. Reserved keys:
	//   environment   — sandbox | production
	//   rotated_by    — last-rotation actor id
	//   rotation_due  — RFC3339 timestamp
	Tags map[string]string
}
