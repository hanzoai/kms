// Package store bootstraps and provides access to Base collections for the KMS.
package store

import (
	"fmt"

	"github.com/hanzoai/base/core"
)

// Bootstrap creates all KMS collections if they don't already exist.
func Bootstrap(app core.App) error {
	collections := []struct {
		name    string
		fields  []*fieldDef
		indexes []string
	}{
		{
			name: "kms_secrets",
			fields: []*fieldDef{
				{name: "org_id", kind: "text", required: true},
				{name: "path", kind: "text", required: true},
				{name: "name", kind: "text", required: true},
				{name: "env", kind: "text", required: false},
				{name: "ciphertext", kind: "text", required: true},
				{name: "wrapped_dek", kind: "text", required: true},
			},
			indexes: []string{
				"CREATE UNIQUE INDEX idx_kms_secrets_org_path ON kms_secrets (org_id, path, name)",
			},
		},
		{
			name: "kms_members",
			fields: []*fieldDef{
				{name: "org_id", kind: "text", required: true},
				{name: "member_id", kind: "text", required: true},
				{name: "pub_key", kind: "text", required: true},
				{name: "wrapped_cek", kind: "text", required: true},
			},
			indexes: []string{
				"CREATE UNIQUE INDEX idx_kms_members_org_mid ON kms_members (org_id, member_id)",
			},
		},
		{
			name: "kms_validator_keys",
			fields: []*fieldDef{
				{name: "validator_id", kind: "text", required: true},
				{name: "data", kind: "json", required: true},
			},
			indexes: []string{
				"CREATE UNIQUE INDEX idx_kms_vkeys_vid ON kms_validator_keys (validator_id)",
			},
		},
		{
			name: "kms_audit_log",
			fields: []*fieldDef{
				{name: "org_id", kind: "text", required: true},
				{name: "seq", kind: "number", required: true},
				{name: "entry", kind: "json", required: true},
				{name: "hash", kind: "text", required: true},
				{name: "prev_hash", kind: "text", required: true},
				// Denormalized query fields for the /v1/kms/audit surface.
				{name: "actor_id", kind: "text", required: false},
				{name: "action", kind: "text", required: false},
				{name: "subject_id", kind: "text", required: false},
			},
			indexes: []string{
				// R2-6: UNIQUE on (org_id, seq) — DB is now the source of
				// truth for seq ordering. Two replicas racing to append the
				// same seq will get SQLSTATE 23505; Append retries.
				"CREATE UNIQUE INDEX uq_kms_audit_org_seq ON kms_audit_log (org_id, seq)",
				"CREATE INDEX idx_kms_audit_actor ON kms_audit_log (actor_id)",
				"CREATE INDEX idx_kms_audit_action ON kms_audit_log (action)",
			},
		},
		{
			name: "kms_idempotency",
			fields: []*fieldDef{
				// R2-7: scoped_key = tenantID || NUL || secretID || NUL || headerKey
				{name: "scoped_key", kind: "text", required: true},
				{name: "expires_at", kind: "text", required: true},
			},
			indexes: []string{
				"CREATE UNIQUE INDEX uq_kms_idem_key ON kms_idempotency (scoped_key)",
				"CREATE INDEX idx_kms_idem_expires ON kms_idempotency (expires_at)",
			},
		},
		{
			name: "kms_service_secrets",
			fields: []*fieldDef{
				{name: "org_id", kind: "text", required: true},
				{name: "path", kind: "text", required: true},
				{name: "name", kind: "text", required: true},
				{name: "value", kind: "text", required: true},
				{name: "secret_type", kind: "text", required: false},
				{name: "status", kind: "text", required: false},
				{name: "metadata", kind: "json", required: false},
				{name: "rotated_at", kind: "text", required: false},
			},
			indexes: []string{
				"CREATE UNIQUE INDEX idx_kms_svc_secrets_org_path ON kms_service_secrets (org_id, path, name)",
			},
		},
		{
			name: "kms_secret_versions",
			fields: []*fieldDef{
				{name: "secret_id", kind: "text", required: true},
				{name: "version", kind: "number", required: true},
				{name: "status", kind: "text", required: true},
				{name: "value", kind: "text", required: false},
				{name: "destroyed_at", kind: "text", required: false},
			},
			indexes: []string{
				"CREATE UNIQUE INDEX idx_kms_secret_versions_sid_ver ON kms_secret_versions (secret_id, version)",
			},
		},
		{
			name: "kms_tenants",
			fields: []*fieldDef{
				{name: "tenant_id", kind: "text", required: true},
				{name: "name", kind: "text", required: true},
				{name: "entity_type", kind: "text", required: true},
				{name: "environment", kind: "text", required: true},
				{name: "allowed_services", kind: "json", required: false},
				{name: "allowed_chains", kind: "json", required: false},
			},
			indexes: []string{
				"CREATE UNIQUE INDEX idx_kms_tenants_tid ON kms_tenants (tenant_id)",
			},
		},
		{
			name: "kms_tenant_configs",
			fields: []*fieldDef{
				{name: "tenant_id", kind: "text", required: true},
				{name: "bindings", kind: "json", required: false},
				{name: "feature_flags", kind: "json", required: false},
			},
			indexes: []string{
				"CREATE UNIQUE INDEX idx_kms_tenant_configs_tid ON kms_tenant_configs (tenant_id)",
			},
		},
		{
			name: "kms_integrations",
			fields: []*fieldDef{
				{name: "tenant_id", kind: "text", required: true},
				{name: "provider", kind: "text", required: true},
				{name: "status", kind: "text", required: true},
				{name: "secret_refs", kind: "json", required: false},
				{name: "config", kind: "json", required: false},
			},
			indexes: []string{
				"CREATE INDEX idx_kms_integrations_tid_prov ON kms_integrations (tenant_id, provider)",
			},
		},
		{
			name: "kms_transit_keys",
			fields: []*fieldDef{
				{name: "name", kind: "text", required: true},
				{name: "key_type", kind: "text", required: true},
				{name: "latest_version", kind: "number", required: true},
				{name: "key_ring", kind: "json", required: true},
				{name: "exportable", kind: "bool", required: false},
			},
			indexes: []string{
				"CREATE UNIQUE INDEX idx_kms_transit_name ON kms_transit_keys (name)",
			},
		},
	}

	for _, c := range collections {
		if _, err := app.FindCollectionByNameOrId(c.name); err == nil {
			continue // already exists
		}
		col := core.NewBaseCollection(c.name)
		for _, f := range c.fields {
			addField(col, f)
		}
		col.Indexes = c.indexes
		if err := app.Save(col); err != nil {
			return fmt.Errorf("store: create collection %s: %w", c.name, err)
		}
	}
	return nil
}

type fieldDef struct {
	name     string
	kind     string
	required bool
}

func addField(col *core.Collection, f *fieldDef) {
	switch f.kind {
	case "text":
		col.Fields.Add(&core.TextField{Name: f.name, Required: f.required})
	case "json":
		col.Fields.Add(&core.JSONField{Name: f.name, MaxSize: 1 << 20})
	case "number":
		col.Fields.Add(&core.NumberField{Name: f.name, Required: f.required})
	case "bool":
		col.Fields.Add(&core.BoolField{Name: f.name})
	}
}
