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
