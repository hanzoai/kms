// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import "github.com/luxfi/math/set"

var (
	// ActivatedACPs is the set of ACPs that are activated.
	//
	// See: https://github.com/orgs/luxfi/projects/1
	ActivatedACPs = set.Of[uint32](
		// Durango:
		23, // https://github.com/luxfi/ACPs/blob/main/ACPs/23-p-chain-native-transfers/README.md
		24, // https://github.com/luxfi/ACPs/blob/main/ACPs/24-shanghai-eips/README.md
		25, // https://github.com/luxfi/ACPs/blob/main/ACPs/25-vm-application-errors/README.md
		30, // https://github.com/luxfi/ACPs/blob/main/ACPs/30-lux-warp-x-evm/README.md
		31, // https://github.com/luxfi/ACPs/blob/main/ACPs/31-enable-chain-ownership-transfer/README.md
		41, // https://github.com/luxfi/ACPs/blob/main/ACPs/41-remove-pending-stakers/README.md
		62, // https://github.com/luxfi/ACPs/blob/main/ACPs/62-disable-addvalidatortx-and-adddelegatortx/README.md

		// Etna:
		77,  // https://github.com/luxfi/ACPs/blob/main/ACPs/77-reinventing-chains/README.md
		103, // https://github.com/luxfi/ACPs/blob/main/ACPs/103-dynamic-fees/README.md
		118, // https://github.com/luxfi/ACPs/blob/main/ACPs/118-warp-signature-request/README.md
		125, // https://github.com/luxfi/ACPs/blob/main/ACPs/125-basefee-reduction/README.md
		131, // https://github.com/luxfi/ACPs/blob/main/ACPs/131-cancun-eips/README.md
		151, // https://github.com/luxfi/ACPs/blob/main/ACPs/151-use-current-block-pchain-height-as-context/README.md
	)

	// CurrentACPs is the set of ACPs that are currently, at the time of
	// release, marked as implementable and not activated.
	//
	// See: https://github.com/orgs/luxfi/projects/1
	CurrentACPs = set.Of[uint32](
		176, // https://github.com/luxfi/ACPs/blob/main/ACPs/176-dynamic-evm-gas-limit-and-price-discovery-updates/README.md
	)

	// ScheduledACPs are the ACPs included into the next upgrade.
	ScheduledACPs = set.Of[uint32](
		176, // https://github.com/luxfi/ACPs/blob/main/ACPs/176-dynamic-evm-gas-limit-and-price-discovery-updates/README.md
	)

	// CurrentLPs is the set of supported Lux Protocols
	CurrentLPs = set.Of[uint32](176)

	// ScheduledLPs are the LPs included in the next upgrade
	ScheduledLPs = set.Of[uint32](176)

	// ActivatedLPs is the set of activated LPs
	ActivatedLPs = set.Of[uint32](176)
)
