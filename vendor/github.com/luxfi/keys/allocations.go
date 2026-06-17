// Copyright (C) 2024-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keys

import (
	"fmt"

	"github.com/luxfi/address"
	"github.com/luxfi/constants"
)

// Unit constants for LUX amounts
const (
	MicroLux uint64 = 1                       // Base unit (6 decimals)
	Lux      uint64 = 1_000_000               // 10^6 microLux
	KiloLux  uint64 = 1_000 * Lux             // 10^9
	MegaLux  uint64 = 1_000_000 * Lux         // 10^12
	GigaLux  uint64 = 1_000_000_000 * Lux     // 10^15 (1B LUX)
	TeraLux  uint64 = 1_000_000_000_000 * Lux // 10^18 (1T LUX)

	// C-chain uses 18 decimals (wei), P/X-chain use 6 decimals
	// Multiply P-chain amount by this to get C-chain wei
	CChainDecimalShift = 1_000_000_000_000 // 10^12

	// Default validator stake: 1M LUX
	DefaultValidatorStake = MegaLux

	// Default fee account amount: 10M LUX (for chain creation, transactions)
	DefaultFeeAccountAmount = 10 * MegaLux
)

// Allocation represents a P-chain genesis allocation
type Allocation struct {
	// ETHAddr is the C-chain compatible address (0x...)
	ETHAddr string `json:"evmAddr"`

	// LUXAddr is the P/X-chain address (P-lux1...)
	LUXAddr string `json:"utxoAddr"`

	// InitialAmount is immediately available on X-chain (usually 0)
	InitialAmount uint64 `json:"initialAmount"`

	// UnlockSchedule defines when funds become available on P-chain
	UnlockSchedule []LockedAmount `json:"unlockSchedule"`
}

// LockedAmount represents a locked amount with unlock time
type LockedAmount struct {
	Amount   uint64 `json:"amount"`
	Locktime uint64 `json:"locktime"`
}

// Staker represents an initial validator in genesis
type Staker struct {
	NodeID        string  `json:"nodeID"`
	RewardAddress string  `json:"rewardAddress"`
	DelegationFee uint32  `json:"delegationFee"`
	Signer        *Signer `json:"signer,omitempty"`
}

// Signer contains BLS key information for a validator
type Signer struct {
	PublicKey         string `json:"publicKey"`
	ProofOfPossession string `json:"proofOfPossession"`
}

// CChainAlloc represents a C-chain genesis allocation
type CChainAlloc struct {
	Balance string `json:"balance"` // Hex-encoded wei amount
}

// GenesisAllocations contains all allocations for network genesis
type GenesisAllocations struct {
	// P-chain allocations
	PChainAllocations []Allocation `json:"allocations"`

	// Initial staked funds (addresses that are staked at genesis)
	InitialStakedFunds []string `json:"initialStakedFunds"`

	// Initial stakers (validators at genesis)
	InitialStakers []Staker `json:"initialStakers"`

	// C-chain allocations (address -> balance)
	CChainAllocations map[string]CChainAlloc `json:"cchain"`
}

// AllocationBuilder helps build genesis allocations from validator keys
type AllocationBuilder struct {
	networkID       uint32
	hrp             string
	keys            []*ValidatorKey
	amountPerKey    uint64
	feeAccountIndex int    // Which key gets extra funds for fees
	feeAccountExtra uint64 // Extra amount for fee account
	vestingStart    uint64 // Unix timestamp when vesting starts
	vestingInterval uint64 // Seconds between each unlock
	vestingPeriods  int    // Number of unlock periods
	noVesting       bool   // If true, all funds immediately available
}

// NewAllocationBuilder creates a new builder for the given keys
func NewAllocationBuilder(networkID uint32, keys []*ValidatorKey) *AllocationBuilder {
	hrp := constants.GetHRP(networkID)
	return &AllocationBuilder{
		networkID:       networkID,
		hrp:             hrp,
		keys:            keys,
		amountPerKey:    DefaultValidatorStake,
		feeAccountIndex: 0,
		feeAccountExtra: DefaultFeeAccountAmount,
		vestingStart:    1577836800,         // Jan 1, 2020
		vestingInterval: 365 * 24 * 60 * 60, // 1 year
		vestingPeriods:  100,                // 100 years
		noVesting:       false,
	}
}

// WithAmount sets the amount per validator
func (ab *AllocationBuilder) WithAmount(amount uint64) *AllocationBuilder {
	ab.amountPerKey = amount
	return ab
}

// WithFeeAccount sets which validator gets extra funds for fees
func (ab *AllocationBuilder) WithFeeAccount(index int, extra uint64) *AllocationBuilder {
	ab.feeAccountIndex = index
	ab.feeAccountExtra = extra
	return ab
}

// WithVesting configures the vesting schedule
func (ab *AllocationBuilder) WithVesting(start uint64, interval uint64, periods int) *AllocationBuilder {
	ab.vestingStart = start
	ab.vestingInterval = interval
	ab.vestingPeriods = periods
	ab.noVesting = false
	return ab
}

// WithNoVesting makes all funds immediately available
func (ab *AllocationBuilder) WithNoVesting() *AllocationBuilder {
	ab.noVesting = true
	return ab
}

// WithImmediateUnlock makes funds immediately unlocked (locktime=0)
func (ab *AllocationBuilder) WithImmediateUnlock() *AllocationBuilder {
	ab.vestingStart = 0
	ab.vestingInterval = 0
	ab.vestingPeriods = 1
	ab.noVesting = true
	return ab
}

// Build creates the genesis allocations
func (ab *AllocationBuilder) Build() (*GenesisAllocations, error) {
	if len(ab.keys) == 0 {
		return nil, fmt.Errorf("no keys provided")
	}

	result := &GenesisAllocations{
		PChainAllocations:  make([]Allocation, len(ab.keys)),
		InitialStakedFunds: make([]string, len(ab.keys)),
		InitialStakers:     make([]Staker, len(ab.keys)),
		CChainAllocations:  make(map[string]CChainAlloc),
	}

	for i, key := range ab.keys {
		// Calculate amount for this key
		amount := ab.amountPerKey
		if i == ab.feeAccountIndex {
			amount += ab.feeAccountExtra
		}

		// Format addresses
		pChainAddr, err := address.Format("P", ab.hrp, key.PChainAddr[:])
		if err != nil {
			return nil, fmt.Errorf("failed to format P-chain address for key %d: %w", i, err)
		}
		ethAddr := key.CChainAddrHex()

		// Build unlock schedule
		var unlockSchedule []LockedAmount
		if ab.noVesting {
			// Immediate unlock
			unlockSchedule = []LockedAmount{{
				Amount:   amount,
				Locktime: 0,
			}}
		} else {
			// Vested unlock over periods
			amountPerPeriod := amount / uint64(ab.vestingPeriods)
			remainder := amount % uint64(ab.vestingPeriods)

			unlockSchedule = make([]LockedAmount, ab.vestingPeriods)
			for p := 0; p < ab.vestingPeriods; p++ {
				periodAmount := amountPerPeriod
				if p == ab.vestingPeriods-1 {
					periodAmount += remainder // Add remainder to last period
				}
				unlockSchedule[p] = LockedAmount{
					Amount:   periodAmount,
					Locktime: ab.vestingStart + uint64(p)*ab.vestingInterval,
				}
			}
		}

		// P-chain allocation (uses P-chain address for unlocking)
		result.PChainAllocations[i] = Allocation{
			ETHAddr:        ethAddr,
			LUXAddr:        pChainAddr,
			InitialAmount:  0, // X-chain initial (usually 0)
			UnlockSchedule: unlockSchedule,
		}

		// Mark as initially staked (uses P-chain address)
		result.InitialStakedFunds[i] = pChainAddr

		// Initial staker
		staker := Staker{
			NodeID:        key.NodeID.String(),
			RewardAddress: pChainAddr,
			DelegationFee: 20000, // 2%
		}

		// Add BLS signer if available
		if len(key.BLSPublicKey) > 0 {
			staker.Signer = &Signer{
				PublicKey:         key.BLSPublicKeyHex(),
				ProofOfPossession: key.BLSPoPHex(),
			}
		}
		result.InitialStakers[i] = staker

		// C-chain allocation (convert to wei: amount * 10^12)
		cchainBalance := amount * CChainDecimalShift
		result.CChainAllocations[ethAddr] = CChainAlloc{
			Balance: fmt.Sprintf("0x%x", cchainBalance),
		}
	}

	return result, nil
}

// QuickAllocations creates allocations with immediate unlock for testing
func QuickAllocations(networkID uint32, keys []*ValidatorKey, amountPerKey uint64) (*GenesisAllocations, error) {
	return NewAllocationBuilder(networkID, keys).
		WithAmount(amountPerKey).
		WithImmediateUnlock().
		Build()
}

// TestnetAllocations creates allocations suitable for testnet (no vesting)
func TestnetAllocations(networkID uint32, keys []*ValidatorKey) (*GenesisAllocations, error) {
	return NewAllocationBuilder(networkID, keys).
		WithAmount(100*MegaLux).       // 100M LUX per validator
		WithFeeAccount(0, 10*MegaLux). // First validator gets extra
		WithNoVesting().
		Build()
}

// MainnetAllocations creates allocations suitable for mainnet (100-year vesting)
func MainnetAllocations(networkID uint32, keys []*ValidatorKey) (*GenesisAllocations, error) {
	return NewAllocationBuilder(networkID, keys).
		WithAmount(GigaLux). // 1B LUX per validator
		WithVesting(
			1577836800,   // Jan 1, 2020
			365*24*60*60, // 1 year intervals
			100,          // 100 periods
		).
		Build()
}

// GenerateAndAllocate generates keys and creates allocations in one step
func GenerateAndAllocate(keyStore *KeyStore, networkID uint32, count int, prefix string, amountPerKey uint64) (*GenesisAllocations, error) {
	keys, err := keyStore.GenerateMultiple(count, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	return NewAllocationBuilder(networkID, keys).
		WithAmount(amountPerKey).
		WithImmediateUnlock().
		Build()
}

// LoadAndAllocate loads existing keys and creates allocations
func LoadAndAllocate(keyStore *KeyStore, networkID uint32, amountPerKey uint64) (*GenesisAllocations, error) {
	keys, err := keyStore.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	return NewAllocationBuilder(networkID, keys).
		WithAmount(amountPerKey).
		WithImmediateUnlock().
		Build()
}
