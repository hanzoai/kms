package accel

// DEXOps provides GPU-accelerated DEX (decentralized exchange) operations.
type DEXOps interface {
	// ConstantProductSwap computes AMM swap output using x*y=k formula.
	// reserveX: [N] uint64 - X token reserves
	// reserveY: [N] uint64 - Y token reserves
	// amountIn: [N] uint64 - input amounts
	// xToY: true for X→Y swap, false for Y→X
	// amountOut: [N] uint64 - output amounts
	// fee: fee percentage (e.g., 0.003 for 0.3%)
	ConstantProductSwap(reserveX, reserveY, amountIn *UntypedTensor, xToY bool, amountOut *UntypedTensor, fee float32) error

	// ConstantProductSwapBatch processes multiple swaps.
	// reserves: [M, 2] uint64 (reserveX, reserveY per pool)
	// swaps: [N, 3] uint64 (poolIndex, amountIn, direction)
	// amounts: [N] uint64 output amounts
	ConstantProductSwapBatch(reserves, swaps, amounts *UntypedTensor, fee float32) error

	// ComputeTWAP computes time-weighted average price.
	// prices: [N] uint64 - historical prices
	// timestamps: [N] uint64 - timestamps
	// start, end: time range
	// twap: [1] uint64 output
	ComputeTWAP(prices, timestamps *UntypedTensor, start, end uint64, twap *UntypedTensor) error

	// MatchOrders matches bid/ask orders.
	// bids: [N, 3] uint64 (price, quantity, orderId)
	// asks: [M, 3] uint64 (price, quantity, orderId)
	// matches: output (bidId, askId, quantity, price)
	// prices: fill prices
	// amounts: fill amounts
	MatchOrders(bids, asks, matches, prices, amounts *UntypedTensor) error

	// MatchOrdersWithPriority matches orders with time/price priority.
	// bids: [N, 4] uint64 (price, quantity, orderId, timestamp)
	// asks: [M, 4] uint64
	MatchOrdersWithPriority(bids, asks, matches *UntypedTensor) error

	// ComputeLiquidity computes concentrated liquidity positions (Uniswap V3 style).
	// tickLower: [N] int32 - lower tick
	// tickUpper: [N] int32 - upper tick
	// amounts: [N, 2] uint64 (amount0, amount1)
	// liquidity: [N] uint128 output
	ComputeLiquidity(tickLower, tickUpper, amounts, liquidity *UntypedTensor) error

	// ComputePositionValue computes position value at current price.
	// liquidity: [N] uint128
	// tickLower: [N] int32
	// tickUpper: [N] int32
	// currentTick: current price tick
	// values: [N, 2] uint64 (token0, token1)
	ComputePositionValue(liquidity, tickLower, tickUpper *UntypedTensor, currentTick int32, values *UntypedTensor) error

	// CalculateFees computes accumulated fees for positions.
	// liquidity: [N] uint128
	// feeGrowthInside0: [N] uint256
	// feeGrowthInside1: [N] uint256
	// fees: [N, 2] uint64 output
	CalculateFees(liquidity, feeGrowthInside0, feeGrowthInside1, fees *UntypedTensor) error

	// BatchSettlement settles multiple trades atomically.
	// trades: [N, 4] uint64 (buyer, seller, token, amount)
	// balances: [M, T] uint64 (M users, T tokens)
	// newBalances: output
	BatchSettlement(trades, balances, newBalances *UntypedTensor) error
}
