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
