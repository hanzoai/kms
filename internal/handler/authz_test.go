package handler

// Authorization matrix tests (F7, F12).

import (
	"os"
	"testing"

	"github.com/hanzoai/kms/internal/auth"
)

func TestSecretAdmin_RequiresMatchingTenant(t *testing.T) {
	t.Setenv("KMS_DEV_MODE", "")
	t.Setenv("KMS_SINGLE_TENANT_ADMIN", "")

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
	t.Setenv("KMS_DEV_MODE", "")
	t.Setenv("KMS_SINGLE_TENANT_ADMIN", "")

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

func TestIsAdmin_DevEscapeHatch_ProdDenied(t *testing.T) {
	// F12: KMS_SINGLE_TENANT_ADMIN must NOT elevate when KMS_DEV_MODE is off,
	// and must NOT elevate when KMS_ENV identifies a production env.
	cases := []struct {
		name    string
		devMode string
		env     string
		want    bool
	}{
		{name: "no_devmode", devMode: "", env: "", want: false},
		{name: "devmode_but_prod", devMode: "true", env: "production", want: false},
		{name: "devmode_prod_alt", devMode: "true", env: "prod", want: false},
		{name: "devmode_mainnet", devMode: "true", env: "mainnet", want: false},
		{name: "devmode_dev", devMode: "true", env: "dev", want: true},
		{name: "devmode_empty_env", devMode: "true", env: "", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("KMS_SINGLE_TENANT_ADMIN", "true")
			os.Setenv("KMS_DEV_MODE", tc.devMode)
			os.Setenv("KMS_ENV", tc.env)
			defer os.Unsetenv("KMS_SINGLE_TENANT_ADMIN")
			defer os.Unsetenv("KMS_DEV_MODE")
			defer os.Unsetenv("KMS_ENV")

			claims := &auth.Claims{Roles: []string{"user"}}
			got := isAdmin(claims)
			if got != tc.want {
				t.Fatalf("isAdmin = %v, want %v (devMode=%q env=%q)", got, tc.want, tc.devMode, tc.env)
			}
		})
	}
}

func TestIsAdmin_AdminClaimAlwaysWins(t *testing.T) {
	t.Setenv("KMS_DEV_MODE", "")
	t.Setenv("KMS_SINGLE_TENANT_ADMIN", "")
	t.Setenv("KMS_ENV", "production")

	claims := &auth.Claims{
		Roles: []string{AdminRoleClaim},
	}
	if !isAdmin(claims) {
		t.Fatal("kms.admin role claim must always elevate regardless of env")
	}
}
