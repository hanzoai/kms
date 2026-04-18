package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/hanzoai/kms/internal/auth"
)

var errForbidden = errors.New("forbidden")

// IAM role claims used by KMS authorization:
//
//   - AdminRoleClaim — full cross-tenant KMS administration (rotate/delete any,
//     create tenants, list across tenants, read tenant-admin scoped routes).
//   - SecretAdminRoleClaim — intra-tenant admin for secrets (create, update,
//     rotate, delete within the caller's tenant).
//   - SecretReadRoleClaim — explicit read-only access to secrets in the
//     caller's tenant. Without this role a tenant member gets the 403 fallback
//     enforced by requireSecretRead.
//
// The tenant's IAM owner/admin roles (mapped by IAM) grant SecretAdmin
// implicitly. Regular tenant members get no secret access by default — they
// must have at least SecretRead.
const (
	AdminRoleClaim       = "kms.admin"
	SecretAdminRoleClaim = "kms.secret.admin"
	SecretReadRoleClaim  = "kms.secret.read"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// hasExactRole reports true iff claims contain the named role exactly.
// Unlike the legacy variadic hasRole in compat.go (which defaults to "admin"
// when claims has no roles), this is a strict, fail-closed check.
func hasExactRole(claims *auth.Claims, role string) bool {
	if claims == nil {
		return false
	}
	for _, r := range claims.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// isAdmin returns true if the caller has the kms.admin IAM role claim.
// No env escape hatch — one way to become admin: the IAM role claim.
func isAdmin(claims *auth.Claims) bool {
	return hasExactRole(claims, AdminRoleClaim)
}

// isSecretAdmin is the intra-tenant secret-admin check. Global admins pass
// through; tenant-scoped admin requires the kms.secret.admin role and a
// matching tenant. For operations that do NOT bind to a specific tenant
// (e.g. service-wide listings) callers must use isAdmin directly.
func isSecretAdmin(claims *auth.Claims, tenantID string) bool {
	if isAdmin(claims) {
		return true
	}
	if claims == nil || tenantID == "" {
		return false
	}
	if claims.Owner != tenantID {
		return false
	}
	return hasExactRole(claims, SecretAdminRoleClaim)
}

// canReadSecret grants read iff the caller is a global admin OR an intra-tenant
// secret admin OR has the explicit kms.secret.read role scoped to the tenant.
func canReadSecret(claims *auth.Claims, tenantID string) bool {
	if isAdmin(claims) {
		return true
	}
	if claims == nil || claims.Owner != tenantID {
		return false
	}
	return hasExactRole(claims, SecretReadRoleClaim) || hasExactRole(claims, SecretAdminRoleClaim)
}
