package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/hanzoai/kms/internal/auth"
)

var errForbidden = errors.New("forbidden")

// AdminRoleClaim is the IAM role name granting cross-tenant KMS administration.
const AdminRoleClaim = "kms.admin"

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// isAdmin returns true if the caller has the kms.admin IAM role claim. A
// single-tenant dev override is honored via KMS_SINGLE_TENANT_ADMIN=true.
func isAdmin(claims *auth.Claims) bool {
	if claims == nil {
		return false
	}
	for _, r := range claims.Roles {
		if r == AdminRoleClaim {
			return true
		}
	}
	return os.Getenv("KMS_SINGLE_TENANT_ADMIN") == "true"
}
