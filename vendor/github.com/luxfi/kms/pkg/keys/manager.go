package keys

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/luxfi/kms/pkg/mpc"
)

// Store is the interface the manager uses to persist key metadata.
type Store interface {
	Put(ks *ValidatorKeySet) error
	Update(ks *ValidatorKeySet) error
	Get(validatorID string) (*ValidatorKeySet, error)
	List() []*ValidatorKeySet
	Delete(validatorID string) error
}

// Signer handles MPC signing operations (M-Chain / MPC daemon).
// FROST (Ed25519) and CGGMP21 (secp256k1) threshold signatures.
type Signer interface {
	Keygen(ctx context.Context, vaultID string, req mpc.KeygenRequest) (*mpc.KeygenResult, error)
	Sign(ctx context.Context, req mpc.SignRequest) (*mpc.SignResult, error)
	Reshare(ctx context.Context, walletID string, req mpc.ReshareRequest) error
	GetWallet(ctx context.Context, walletID string) (*mpc.Wallet, error)
	Status(ctx context.Context) (*mpc.ClusterStatus, error)
}

// Encryptor handles threshold FHE operations (T-Chain).
// TFHE for secret decrypt, CKKS for ML inference.
type Encryptor interface {
	Encrypt(ctx context.Context, keyID string, plaintext []byte) (*mpc.EncryptResult, error)
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*mpc.DecryptResult, error)
}

// MPCBackend combines Signer + Encryptor for implementations that provide both
// (e.g. ZapClient talks to a single MPC daemon that does signing + FHE).
type MPCBackend interface {
	Signer
	Encryptor
}

// Manager orchestrates validator key lifecycle.
// K-Chain concern: key registry, policy, metadata.
// Delegates signing to Signer (M-Chain) and encryption to Encryptor (T-Chain).
type Manager struct {
	signer    Signer
	encryptor Encryptor
	store     Store
	vaultID   string
}

// NewManager creates a key manager.
// backend implements both Signer and Encryptor (today: single MPC daemon).
// When M-Chain and T-Chain are separate, pass them individually via NewManagerSplit.
func NewManager(backend MPCBackend, store Store, vaultID string) *Manager {
	return &Manager{
		signer:    backend,
		encryptor: backend,
		store:     store,
		vaultID:   vaultID,
	}
}

// NewManagerSplit creates a manager with separate signer and encryptor backends.
// Use when M-Chain (signing) and T-Chain (FHE) are separate chains.
func NewManagerSplit(signer Signer, encryptor Encryptor, store Store, vaultID string) *Manager {
	return &Manager{
		signer:    signer,
		encryptor: encryptor,
		store:     store,
		vaultID:   vaultID,
	}
}

// GenerateValidatorKeys creates a new validator key set via MPC DKG.
// It generates two MPC wallets: one for BLS (secp256k1/CGGMP21) and one for
// Corona (ed25519/FROST), then stores the mapping.
func (m *Manager) GenerateValidatorKeys(ctx context.Context, req GenerateRequest) (*ValidatorKeySet, error) {
	if req.ValidatorID == "" {
		return nil, fmt.Errorf("keys: validator_id is required")
	}
	if req.Threshold < 2 {
		return nil, fmt.Errorf("keys: threshold must be >= 2")
	}
	if req.Parties < req.Threshold {
		return nil, fmt.Errorf("keys: parties must be >= threshold")
	}

	// Check for duplicate.
	if _, err := m.store.Get(req.ValidatorID); err == nil {
		return nil, fmt.Errorf("keys: validator %s already exists", req.ValidatorID)
	}

	// Generate BLS key (secp256k1 via CGGMP21 protocol).
	blsResult, err := m.signer.Keygen(ctx, m.vaultID, mpc.KeygenRequest{
		Name:     fmt.Sprintf("validator-%s-bls", req.ValidatorID),
		KeyType:  "secp256k1",
		Protocol: "cggmp21",
	})
	if err != nil {
		return nil, fmt.Errorf("keys: bls keygen failed: %w", err)
	}

	// Generate Corona key (ed25519 via FROST protocol).
	coronaResult, err := m.signer.Keygen(ctx, m.vaultID, mpc.KeygenRequest{
		Name:     fmt.Sprintf("validator-%s-corona", req.ValidatorID),
		KeyType:  "ed25519",
		Protocol: "frost",
	})
	if err != nil {
		// BLS keygen succeeded but Corona failed. DKG cannot be rolled back —
		// the BLS wallet is now orphaned in the MPC cluster. Log for manual cleanup.
		log.Printf("keys: CRITICAL: corona keygen failed after BLS keygen succeeded; orphaned BLS wallet_id=%s for validator=%s — manual cleanup required: %v",
			blsResult.WalletID, req.ValidatorID, err)
		return nil, fmt.Errorf("keys: corona keygen failed (orphaned bls wallet %s): %w", blsResult.WalletID, err)
	}

	blsPub := ""
	if blsResult.ECDSAPubkey != nil {
		blsPub = *blsResult.ECDSAPubkey
	}
	coronaPub := ""
	if coronaResult.EDDSAPubkey != nil {
		coronaPub = *coronaResult.EDDSAPubkey
	}

	now := time.Now().UTC()
	ks := &ValidatorKeySet{
		ValidatorID:       req.ValidatorID,
		BLSWalletID:       blsResult.WalletID,
		CoronaWalletID:  coronaResult.WalletID,
		BLSPublicKey:      blsPub,
		CoronaPublicKey: coronaPub,
		Threshold:         blsResult.Threshold,
		Parties:           len(blsResult.Participants),
		Status:            "active",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := m.store.Put(ks); err != nil {
		return nil, fmt.Errorf("keys: store put: %w", err)
	}

	return ks, nil
}

// SignWithBLS signs a message using the validator's BLS key via MPC threshold signing.
func (m *Manager) SignWithBLS(ctx context.Context, validatorID string, message []byte) (*SignResponse, error) {
	ks, err := m.store.Get(validatorID)
	if err != nil {
		return nil, fmt.Errorf("keys: validator %s: %w", validatorID, err)
	}

	result, err := m.signer.Sign(ctx, mpc.SignRequest{
		WalletID: ks.BLSWalletID,
		KeyType:  "secp256k1",
		Message:  message,
	})
	if err != nil {
		return nil, fmt.Errorf("keys: bls sign: %w", err)
	}

	return &SignResponse{
		Signature: result.Signature,
		R:         result.R,
		S:         result.S,
	}, nil
}

// SignWithRingtail signs a message using the validator's Corona key via MPC threshold signing.
func (m *Manager) SignWithRingtail(ctx context.Context, validatorID string, message []byte) (*SignResponse, error) {
	ks, err := m.store.Get(validatorID)
	if err != nil {
		return nil, fmt.Errorf("keys: validator %s: %w", validatorID, err)
	}

	result, err := m.signer.Sign(ctx, mpc.SignRequest{
		WalletID: ks.CoronaWalletID,
		KeyType:  "ed25519",
		Message:  message,
	})
	if err != nil {
		return nil, fmt.Errorf("keys: corona sign: %w", err)
	}

	return &SignResponse{
		Signature: result.Signature,
		R:         result.R,
		S:         result.S,
	}, nil
}

// Rotate reshares a validator's keys with new threshold or participants.
func (m *Manager) Rotate(ctx context.Context, validatorID string, req RotateRequest) (*ValidatorKeySet, error) {
	ks, err := m.store.Get(validatorID)
	if err != nil {
		return nil, fmt.Errorf("keys: validator %s: %w", validatorID, err)
	}

	reshareReq := mpc.ReshareRequest{
		NewThreshold:    req.NewThreshold,
		NewParticipants: req.NewParticipants,
	}

	// Build rollback params from current state.
	rollbackReq := mpc.ReshareRequest{
		NewThreshold:    ks.Threshold,
		NewParticipants: nil, // same participant set
	}

	// Reshare BLS key.
	if err := m.signer.Reshare(ctx, ks.BLSWalletID, reshareReq); err != nil {
		return nil, fmt.Errorf("keys: bls reshare: %w", err)
	}

	// Reshare Corona key.
	if err := m.signer.Reshare(ctx, ks.CoronaWalletID, reshareReq); err != nil {
		// BLS was reshared but Corona failed — keys are now inconsistent.
		// Attempt to roll BLS back to previous threshold/participants.
		log.Printf("keys: WARNING: corona reshare failed after BLS reshare succeeded for validator=%s, attempting BLS rollback: %v",
			validatorID, err)
		if rbErr := m.signer.Reshare(ctx, ks.BLSWalletID, rollbackReq); rbErr != nil {
			log.Printf("keys: CRITICAL: BLS rollback also failed for validator=%s — keys are in inconsistent state, manual intervention required: %v",
				validatorID, rbErr)
			return nil, fmt.Errorf("keys: corona reshare failed AND bls rollback failed (inconsistent state): corona=%w, bls_rollback=%v", err, rbErr)
		}
		log.Printf("keys: BLS rollback succeeded for validator=%s after corona reshare failure", validatorID)
		return nil, fmt.Errorf("keys: corona reshare failed (bls rolled back): %w", err)
	}

	if req.NewThreshold > 0 {
		ks.Threshold = req.NewThreshold
	}
	if len(req.NewParticipants) > 0 {
		ks.Parties = len(req.NewParticipants)
	}
	ks.UpdatedAt = time.Now().UTC()

	if err := m.store.Update(ks); err != nil {
		return nil, fmt.Errorf("keys: store update: %w", err)
	}

	return ks, nil
}

// Get retrieves a validator key set.
func (m *Manager) Get(validatorID string) (*ValidatorKeySet, error) {
	return m.store.Get(validatorID)
}

// List returns all validator key sets.
func (m *Manager) List() []*ValidatorKeySet {
	return m.store.List()
}
