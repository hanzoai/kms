package handler

import (
	"net/http"

	"github.com/hanzoai/kms/internal/mpc"
)

// Status handles health and status endpoints.
type Status struct {
	mpc *mpc.ZapClient
}

// NewStatus creates a status handler.
func NewStatus(m *mpc.ZapClient) *Status {
	return &Status{mpc: m}
}

// Healthz returns 200 OK. No auth required.
// GET /healthz
func (h *Status) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ServerConfig returns Infisical-compatible server config for the frontend.
// GET /api/v1/admin/config
func (h *Status) ServerConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"config": map[string]any{
			"initialized":                           true,
			"allowSignUp":                           false,
			"disableAuditLogStorage":                false,
			"isMigrationModeOn":                     false,
			"trustSamlEmails":                       true,
			"trustLdapEmails":                       true,
			"trustOidcEmails":                       true,
			"isSecretScanningDisabled":               true,
			"kubernetesAutoFetchServiceAccountToken": false,
			"defaultAuthOrgSlug":                    nil,
			"defaultAuthOrgId":                      nil,
			"enabledLoginMethods":                   []string{"oidc"},
			"invalidatingCache":                     false,
			"fipsEnabled":                           false,
			"paramsFolderSecretDetectionEnabled":     false,
			"isOfflineUsageReportsEnabled":           false,
		},
	})
}

// StatusCheck returns KMS + MPC cluster status.
// GET /v1/status
func (h *Status) StatusCheck(w http.ResponseWriter, r *http.Request) {
	mpcStatus, err := h.mpc.Status(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"kms": "ok",
			"mpc": "unreachable",
			"error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"kms": "ok",
		"mpc": mpcStatus,
	})
}
