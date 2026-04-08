package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/transit"
)

// Transit handles transit encryption endpoints.
type Transit struct {
	engine *transit.Engine
}

// NewTransit creates a transit handler.
func NewTransit(e *transit.Engine) *Transit {
	return &Transit{engine: e}
}

// CreateKey creates a new transit key.
// POST /v1/transit/keys
func (h *Transit) CreateKey(w http.ResponseWriter, r *http.Request) {
	var req transit.CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Type == "" {
		req.Type = transit.KeyTypeAES256GCM
	}

	if err := h.engine.CreateKey(req); err != nil {
		if err == transit.ErrUnknownKeyType {
			writeError(w, http.StatusBadRequest, "unknown key type")
			return
		}
		writeError(w, http.StatusConflict, "key already exists")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": req.Name, "type": req.Type})
}

// Encrypt encrypts plaintext with a named AES-256-GCM key.
// POST /v1/transit/encrypt/{name}
func (h *Transit) Encrypt(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var req transit.EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Plaintext == "" {
		writeError(w, http.StatusBadRequest, "plaintext is required (base64-encoded)")
		return
	}

	resp, err := h.engine.Encrypt(name, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Decrypt decrypts ciphertext with a named AES-256-GCM key.
// POST /v1/transit/decrypt/{name}
func (h *Transit) Decrypt(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var req transit.DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Ciphertext == "" {
		writeError(w, http.StatusBadRequest, "ciphertext is required")
		return
	}

	resp, err := h.engine.Decrypt(name, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Sign signs a message with a named Ed25519 key.
// POST /v1/transit/sign/{name}
func (h *Transit) Sign(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var req transit.SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input is required (base64-encoded)")
		return
	}

	resp, err := h.engine.Sign(name, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Verify verifies a signature with a named Ed25519 key.
// POST /v1/transit/verify/{name}
func (h *Transit) Verify(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var req transit.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Input == "" || req.Signature == "" {
		writeError(w, http.StatusBadRequest, "input and signature are required")
		return
	}

	resp, err := h.engine.Verify(name, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
