# Lux Math Library

A comprehensive mathematical utilities library for the Lux ecosystem.

## Features

- **Big integer utilities**: `HexOrDecimal256`, `ParseBig256`, `U256`, `BigPow` etc.
- **Safe arithmetic**: Overflow-checked `SafeAdd`, `SafeSub`, `SafeMul`
- **Bit operations**: XOR, AND, compression utilities
- **Set operations**: Efficient set implementations including bit sets
- **Data structures**: Linked lists, hash maps, heaps
- **Averagers**: Time-windowed averaging utilities

## Installation

```bash
go get github.com/luxfi/math
```

## Package Structure

| Package | Description |
|---------|-------------|
| `github.com/luxfi/math` | Root package with re-exports for backwards compatibility |
| `github.com/luxfi/math/big` | Big integer utilities (HexOrDecimal256, U256, parsing) |
| `github.com/luxfi/math/safe` | Overflow-safe arithmetic operations |
| `github.com/luxfi/math/bit` | Bit manipulation utilities |
| `github.com/luxfi/math/set` | Set data structures |
| `github.com/luxfi/math/linked` | Linked data structures |
| `github.com/luxfi/math/heap` | Heap implementations |

## Usage

```go
// Import root package (re-exports from subpackages)
import "github.com/luxfi/math"

// Or import specific subpackages directly
import (
    "github.com/luxfi/math/big"
    "github.com/luxfi/math/safe"
    "github.com/luxfi/math/set"
)
```

### Big Integer Operations

```go
import "github.com/luxfi/math/big"

// Parse hex or decimal
val, _ := big.ParseBig256("0x1234")

// 256-bit unsigned operations
result := big.U256(someInt)

// Power operation
power := big.BigPow(2, 256)
```

### Safe Arithmetic

```go
import "github.com/luxfi/math/safe"

// Returns (result, overflow bool)
sum, overflow := safe.SafeAdd(a, b)
product, overflow := safe.SafeMul(x, y)

// Returns (result, error)
sum, err := safe.Add64(a, b)
```

## License

See the LICENSE file for licensing terms.