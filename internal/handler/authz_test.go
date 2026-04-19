package handler

// Authorization matrix tests (F7).

import (
	"testing"

	"github.com/hanzoai/kms/internal/auth"
)

func TestSecretAdmin_RequiresMatchingTenant(t *testing.T) {
	claims := &auth.Claims{
		Owner: "tenant-A",
		Roles: []string{SecretAdminRoleClaim},
	}
	if !isSecretAdmin(claims, "tenant-A") {
		t.Fatal("secret admin of tenant-A must pass for tenant-A writes")
	}
	if isSecretAdmin(claims, "tenant-B") {
		t.Fatal("secret admin of tenant-A must NOT pass for tenant-B writes (F7)")
	}
}

func TestSecretRead_GrantsReadOnly(t *testing.T) {
	claims := &auth.Claims{
		Owner: "tenant-A",
		Roles: []string{SecretReadRoleClaim},
	}
	if !canReadSecret(claims, "tenant-A") {
		t.Fatal("secret read claim must permit read")
	}
	if isSecretAdmin(claims, "tenant-A") {
		t.Fatal("secret read must NOT imply secret admin (write)")
	}
}

func TestSecretRead_NoRoleDeniesAccess(t *testing.T) {
	// Regular tenant member, no KMS roles — must be denied read.
	claims := &auth.Claims{
		Owner: "tenant-A",
		Roles: []string{"user"},
	}
	if canReadSecret(claims, "tenant-A") {
		t.Fatal("tenant member without kms.secret.read must be denied (F7)")
	}
	if isSecretAdmin(claims, "tenant-A") {
		t.Fatal("tenant member without kms.secret.admin must be denied (F7)")
	}
}

func TestIsAdmin_OnlyAdminRoleElevates(t *testing.T) {
	// No env escape hatch — the ONLY way to be admin is the kms.admin role.
	deny := &auth.Claims{Roles: []string{"user"}}
	if isAdmin(deny) {
		t.Fatal("non-admin role must not elevate to admin")
	}

	grant := &auth.Claims{Roles: []string{AdminRoleClaim}}
	if !isAdmin(grant) {
		t.Fatal("kms.admin role claim must always elevate")
	}
}

// R2-5: regression — even if env escape hatch were re-introduced somehow
// (KMS_SINGLE_TENANT_ADMIN=true, KMS_DEV_MODE=true, no KMS_ENV), the current
// code must NOT elevate. Exercise all three env vars to prove isAdmin ignores
// them entirely.
func TestIsAdmin_IgnoresEnvEscapeHatch(t *testing.T) {
	t.Setenv("KMS_SINGLE_TENANT_ADMIN", "true")
	t.Setenv("KMS_DEV_MODE", "true")
	// Empty KMS_ENV is the classic "I forgot to set it" foot-gun that was
	// fail-open under the deny-list design.
	t.Setenv("KMS_ENV", "")

	deny := &auth.Claims{Roles: []string{"user"}}
	if isAdmin(deny) {
		t.Fatal("R2-5: env escape hatch must not elevate without kms.admin role")
	}
}

// R2-4: regression — plain tenant membership (claims.Owner == tenant) without
// any KMS role must NOT be enough to read tenant secrets, even for metadata.
func TestCanReadSecret_DeniesBareTenantMember(t *testing.T) {
	member := &auth.Claims{Owner: "tenant-A", Roles: []string{"user"}}
	if canReadSecret(member, "tenant-A") {
		t.Fatal("R2-4: plain tenant membership must not grant secret reads")
	}

	// Explicit read role must permit read.
	reader := &auth.Claims{Owner: "tenant-A", Roles: []string{SecretReadRoleClaim}}
	if !canReadSecret(reader, "tenant-A") {
		t.Fatal("kms.secret.read must grant read on own tenant")
	}

	// But not on a different tenant.
	if canReadSecret(reader, "tenant-B") {
		t.Fatal("kms.secret.read must NOT grant cross-tenant reads")
	}
}
