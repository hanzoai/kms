// Package kms — canonical client interface for Hanzo KMS.
//
//	import kms "github.com/hanzoai/kms/sdk/go"
//	var v kms.Vault = kms.NewClient(cfg)

package kms

import (
	"context"
	"errors"
	"time"
)

// Typed errors. Callers branch via errors.Is.
var (
	ErrSecretNotFound      = errors.New("kms: secret not found")
	ErrVersionMismatch     = errors.New("kms: version mismatch")
	ErrVersionNotFound     = errors.New("kms: version not found")
	ErrSecretLocked        = errors.New("kms: secret locked")
	ErrRotateUnsupported   = errors.New("kms: rotation unsupported by backend")
)

// Vault is the secrets-storage surface. Namespaced at construction;
// every method takes leaf names. Goroutine-safe.
type Vault interface {
	// Kind reports the backend identifier
	// (hanzo-kms | aws-secrets-manager | hashicorp-vault | doppler | env).
	Kind() string

	// Get returns the secret value. Empty + non-nil error on missing.
	// The empty + nil case is never returned.
	Get(ctx context.Context, name string) ([]byte, error)

	// GetWithMeta is Get plus the metadata sidecar.
	GetWithMeta(ctx context.Context, name string) ([]byte, SecretMeta, error)

	// Put writes a new version. PutOpts.IfVersion provides
	// compare-and-set: when non-empty, the write returns
	// ErrVersionMismatch unless the current version matches.
	Put(ctx context.Context, name string, value []byte, opts PutOpts) (version string, err error)

	// Rotate generates new material atomically. kind selects the
	// generator (api_key | webhook_secret | dsn_password | jwt_signing_key).
	// Backends without managed rotation return ErrRotateUnsupported;
	// callers fall back to Put with their own generator.
	//
	// Dual-read window: the prior version remains readable via
	// GetVersion(prev) until prevValidUntil. Implementations MUST
	// honor this window for stateless rotations.
	Rotate(ctx context.Context, name, kind string) (rotation Rotation, err error)

	// GetVersion reads a specific historical version. Used by callers
	// holding stale credentials during a rotation grace window.
	GetVersion(ctx context.Context, name, version string) ([]byte, error)

	// List paginates leaf names under prefix. Cursor-based.
	List(ctx context.Context, prefix string, opts ListOpts) (*ListPage, error)
}

// PutOpts configures a Put.
type PutOpts struct {
	// IfVersion is the expected current version. Empty disables the
	// compare-and-set. Mismatch returns ErrVersionMismatch.
	IfVersion string
	// Tags overwrite the metadata Tags sidecar. Empty leaves Tags
	// unchanged.
	Tags map[string]string
}

// Rotation is the result of a Rotate call.
type Rotation struct {
	Name           string
	NewValue       []byte
	NewVersion     string
	PreviousVersion string
	// PreviousValidUntil names when the prior version stops resolving
	// via Get/GetWithMeta (still readable via GetVersion). Zero means
	// no grace window — backends that hard-cut MUST document the
	// breakage in operator runbooks.
	PreviousValidUntil time.Time
}

// SecretMeta is the sidecar returned by GetWithMeta.
type SecretMeta struct {
	Name      string
	Version   string
	CreatedAt time.Time
	UpdatedAt time.Time
	// Tags reserved keys:
	//   environment   — sandbox | production
	//   rotated_by    — last-rotation actor id
	//   rotation_due  — RFC3339 timestamp
	Tags map[string]string
}

// ListOpts is the cursor-pagination shape.
type ListOpts struct {
	Cursor string
	Limit  int // implementations cap at 1000
}

// ListPage is one slice of a List call.
type ListPage struct {
	Items      []string
	NextCursor string
}
