// Package kms — canonical client interface for Hanzo KMS.
//
// Secrets-storage backends (Hanzo KMS, AWS Secrets Manager,
// HashiCorp Vault, Doppler, env-fallback) share the same five
// primitives: Get, GetWithMeta, Put, Rotate, List. This file
// declares the vendor-neutral interface as the canonical type so
// every consumer (BD, ATS, TA, lqd, operator) depends on the
// interface — not the *Client struct. The *Client implementation
// here is the Hanzo-KMS adapter.
//
//   import kms "github.com/hanzoai/kms/sdk/go"
//   var v kms.Vault = kms.NewClient(cfg)
//
// A new backend (AWS, Vault, Doppler) ships as its own package
// satisfying kms.Vault — consumers swap by changing the
// constructor, no call-site edits.

package kms

import (
	"context"
	"time"
)

// Vault is the vendor-neutral secrets-storage surface every
// consumer dials. Goroutine-safe.
//
// Namespacing: a tenant's secret bucket is the namespace prefix
// supplied at Client construction; callers pass only the leaf
// name. Cross-tenant access is impossible through this interface.
type Vault interface {
	// Kind reports the backend identifier ("hanzo-kms",
	// "aws-secrets-manager", "hashicorp-vault", "doppler",
	// "env"). Used for logging + audit; consumers never branch
	// on it.
	Kind() string

	// Get returns the value of leaf-name `name`. Empty string +
	// non-nil error when missing — empty-string with nil error
	// is NEVER returned; the contract is "configured xor error".
	Get(ctx context.Context, name string) (string, error)

	// GetWithMeta is Get + sidecar metadata (version, timestamps,
	// tags). Used by audit + rotation.
	GetWithMeta(ctx context.Context, name string) (string, SecretMeta, error)

	// Put stores a new version of `name`. Returns the new
	// version id where supported; empty string otherwise.
	// Versioning vendors (KMS KV-v2, AWS) keep prior versions;
	// non-versioning vendors (Doppler, env) overwrite.
	Put(ctx context.Context, name, value string) (string, error)

	// Rotate atomically generates new material for a secret of
	// `kind` ("api_key" | "webhook_secret" | "dsn_password" |
	// "jwt_signing_key") and returns the new value + version.
	// Vendors without managed rotation return ErrRotateUnsupported;
	// callers fall back to Put with their own generator.
	Rotate(ctx context.Context, name, kind string) (newValue, version string, err error)

	// List returns leaf names of every secret in the current
	// namespace. Pagination is hidden — impl returns the full set.
	List(ctx context.Context) ([]string, error)
}

// SecretMeta is the metadata sidecar GetWithMeta returns. Vendors
// without certain fields populate as zero-values.
type SecretMeta struct {
	Name      string
	Version   string
	CreatedAt time.Time
	UpdatedAt time.Time
	// Tags is vendor-attached metadata. Common keys:
	//   environment   — sandbox / production
	//   rotated_by    — last-rotation actor (admin user id)
	//   rotation_due  — RFC3339 when rotation is overdue
	Tags map[string]string
}
