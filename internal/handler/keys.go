package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/mpc"
	"github.com/hanzoai/kms/internal/store"
)

// Keys handles validator key lifecycle via the MPC daemon.
type Keys struct {
	store   *store.KeyStore
	mpc     *mpc.ZapClient
	vaultID string
}

// NewKeys creates a keys handler.
func NewKeys(s *store.KeyStore, m *mpc.ZapClient, vaultID string) *Keys {
	return &Keys{store: s, mpc: m, vaultID: vaultID}
}

// Generate creates a new validator key set via MPC DKG.
// POST /v1/keys/generate
func (h *Keys) Generate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ValidatorID string `json:"validator_id"`
		Threshold   int    `json:"threshold"`
		Parties     int    `json:"parties"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ValidatorID == "" {
		writeError(w, http.StatusBadRequest, "validator_id is required")
		return
	}
	if req.Threshold < 2 {
		writeError(w, http.StatusBadRequest, "threshold must be >= 2")
		return
	}
	if req.Parties < req.Threshold {
		writeError(w, http.StatusBadRequest, "parties must be >= threshold")
		return
	}

	// BLS keygen (secp256k1 / CGGMP21).
	blsResult, err := h.mpc.Keygen(r.Context(), h.vaultID, mpc.KeygenRequest{
		Name:     req.ValidatorID + "-bls",
		KeyType:  "ecdsa",
		Protocol: "cggmp21",
	})
	if err != nil {
		log.Printf("kmsd: keygen bls failed validator=%s: %v", req.ValidatorID, err)
		writeError(w, http.StatusInternalServerError, "bls keygen failed")
		return
	}

	// Ringtail keygen (ed25519 / FROST).
	rtResult, err := h.mpc.Keygen(r.Context(), h.vaultID, mpc.KeygenRequest{
		Name:     req.ValidatorID + "-ringtail",
		KeyType:  "eddsa",
		Protocol: "frost",
	})
	if err != nil {
		log.Printf("kmsd: keygen ringtail failed validator=%s: %v", req.ValidatorID, err)
		writeError(w, http.StatusInternalServerError, "ringtail keygen failed")
		return
	}

	ks := &store.ValidatorKeySet{
		ValidatorID:       req.ValidatorID,
		BLSWalletID:       blsResult.WalletID,
		RingtailWalletID:  rtResult.WalletID,
		BLSPublicKey:      derefStr(blsResult.ECDSAPubkey),
		RingtailPublicKey: derefStr(rtResult.EDDSAPubkey),
		Threshold:         req.Threshold,
		Parties:           req.Parties,
		Status:            "active",
	}

	if err := h.store.Put(ks); err != nil {
		if err == store.ErrKeyExists {
			writeError(w, http.StatusConflict, "validator key set already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to store key set")
		return
	}

	log.Printf("kmsd: keygen OK validator=%s bls=%s ringtail=%s", ks.ValidatorID, ks.BLSWalletID, ks.RingtailWalletID)
	writeJSON(w, http.StatusCreated, ks)
}

// List returns all validator key sets.
// GET /v1/keys
func (h *Keys) List(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list keys")
		return
	}
	if list == nil {
		list = []*store.ValidatorKeySet{}
	}
	writeJSON(w, http.StatusOK, list)
}

// Get returns a validator key set by ID.
// GET /v1/keys/{id}
func (h *Keys) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ks, err := h.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "validator key set not found")
		return
	}
	writeJSON(w, http.StatusOK, ks)
}

// Sign signs a message with a validator key.
// POST /v1/keys/{id}/sign
func (h *Keys) Sign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		KeyType string `json:"key_type"` // "bls" or "ringtail"
		Message []byte `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Message) == 0 {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}

	ks, err := h.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "validator key set not found")
		return
	}

	var walletID string
	switch req.KeyType {
	case "bls":
		walletID = ks.BLSWalletID
	case "ringtail":
		walletID = ks.RingtailWalletID
	default:
		writeError(w, http.StatusBadRequest, "key_type must be 'bls' or 'ringtail'")
		return
	}

	result, err := h.mpc.Sign(r.Context(), mpc.SignRequest{
		KeyType:  req.KeyType,
		WalletID: walletID,
		Message:  req.Message,
	})
	if err != nil {
		log.Printf("kmsd: sign failed validator=%s key_type=%s: %v", id, req.KeyType, err)
		writeError(w, http.StatusInternalServerError, "sign failed")
		return
	}

	log.Printf("kmsd: sign OK validator=%s key_type=%s", id, req.KeyType)
	writeJSON(w, http.StatusOK, result)
}

// Rotate reshares a validator's keys with new threshold/participants.
// POST /v1/keys/{id}/rotate
func (h *Keys) Rotate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		NewThreshold    int      `json:"new_threshold,omitempty"`
		NewParticipants []string `json:"new_participants,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewThreshold == 0 && len(req.NewParticipants) == 0 {
		writeError(w, http.StatusBadRequest, "new_threshold or new_participants required")
		return
	}

	ks, err := h.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "validator key set not found")
		return
	}

	reshareReq := mpc.ReshareRequest{
		NewThreshold:    req.NewThreshold,
		NewParticipants: req.NewParticipants,
	}

	// Reshare both wallets.
	if err := h.mpc.Reshare(r.Context(), ks.BLSWalletID, reshareReq); err != nil {
		log.Printf("kmsd: rotate bls failed validator=%s: %v", id, err)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "bls rotate failed")
		return
	}
	if err := h.mpc.Reshare(r.Context(), ks.RingtailWalletID, reshareReq); err != nil {
		log.Printf("kmsd: rotate ringtail failed validator=%s: %v", id, err)
		writeError(w, http.StatusInternalServerError, "ringtail rotate failed")
		return
	}

	if req.NewThreshold > 0 {
		ks.Threshold = req.NewThreshold
	}
	if len(req.NewParticipants) > 0 {
		ks.Parties = len(req.NewParticipants)
	}
	if err := h.store.Update(ks); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update key set")
		return
	}

	log.Printf("kmsd: rotate OK validator=%s threshold=%d parties=%d", id, ks.Threshold, ks.Parties)
	writeJSON(w, http.StatusOK, ks)
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
