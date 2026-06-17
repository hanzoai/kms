# Lux IDs Package

[![Go Reference](https://pkg.go.dev/badge/github.com/luxfi/ids.svg)](https://pkg.go.dev/github.com/luxfi/ids)
[![Go Report Card](https://goreportcard.com/badge/github.com/luxfi/ids)](https://goreportcard.com/report/github.com/luxfi/ids)

## Overview

The `ids` package provides strongly-typed identifiers for the Lux Network. It includes implementations for various ID types used throughout the ecosystem, ensuring type safety and preventing ID misuse.

## Features

- **Type-Safe IDs**: Prevent mixing different ID types at compile time
- **Human-Readable Formats**: CB58 encoding for user-facing representations
- **Efficient Storage**: 32-byte arrays with optimized operations
- **Comprehensive Types**: NodeID, ID, ShortID, and RequestID
- **Deterministic Generation**: Consistent ID generation from inputs
- **Sorting Support**: IDs implement sort.Interface

## Installation

```bash
go get github.com/luxfi/ids
```

## ID Types

### ID
General-purpose 32-byte identifier used for transactions, blocks, chains, and subnets.

```go
import "github.com/luxfi/ids"

// Create from bytes
var idBytes [32]byte
copy(idBytes[:], []byte("some data"))
id := ids.ID(idBytes)

// Parse from string
id, err := ids.FromString("TtF4d2QWbk5vzQGTEPrN48x6vwgAoAmKQ9cbp79inpQmcRKES")

// Convert to string
str := id.String() // CB58 encoded

// Prefix support
prefixedStr := id.PrefixedString(ids.PlatformChainID) // "P-TtF4d2..."

// Empty check
if id == ids.Empty {
    // Handle empty ID
}
```

### NodeID
20-byte identifier for network nodes, derived from TLS certificates.

```go
// From certificate
cert := &ids.Certificate{
    Raw:       tlsCert.Raw,
    PublicKey: tlsCert.PublicKey,
}
nodeID := ids.NodeIDFromCert(cert)

// From string
nodeID, err := ids.NodeIDFromString("NodeID-E5ecNPHk46SaKZYz6WM1PFMvgtU4sQxzG")

// Convert to string
str := nodeID.String() // Always prefixed with "NodeID-"

// Short string (for logs)
shortStr := nodeID.ShortString() // "E5ecNP..."
```

### ShortID
20-byte identifier for addresses.

```go
// Create from bytes
var shortBytes [20]byte
shortID := ids.ShortID(shortBytes)

// Generate from larger data
data := []byte("some larger data")
shortID = ids.ShortID(hashing.ComputeHash160Array(data))

// String conversion
str := shortID.String() // CB58 encoded
```

### RequestID
32-bit identifier for RPC requests.

```go
// Create new request ID
requestID := ids.RequestID(12345)

// String representation
str := requestID.String() // "12345"

// Check if set
if requestID == 0 {
    // Unset request ID
}
```

## Advanced Usage

### ID Generation

```go
// Generate ID from transaction bytes
txBytes := []byte{...}
txID := hashing.ComputeHash256Array(txBytes)

// Generate deterministic IDs
message := []byte("deterministic input")
id := ids.ID(hashing.ComputeHash256Array(message))
```

### Aliasing

```go
// Create aliased ID
chainAlias := ids.Aliaser{}
chainAlias.Alias(ids.ID{1, 2, 3}, "X")

// Lookup by alias
id, err := chainAlias.Lookup("X")

// Reverse lookup
aliases, err := chainAlias.Aliases(id)
```

### Sorting

```go
// IDs are sortable
idSlice := []ids.ID{id1, id2, id3}
sort.Sort(ids.SortIDs(idSlice))

// NodeIDs too
nodeIDs := []ids.NodeID{node1, node2, node3}
sort.Sort(ids.SortNodeIDs(nodeIDs))
```

### Bags (Multisets)

```go
// Create a bag of IDs
bag := ids.NewBag()
bag.Add(id1)
bag.AddCount(id2, 5)

// Check count
count := bag.Count(id2) // returns 5

// Operations
bag.Remove(id1)
list := bag.List() // Unique IDs
```

### Sets

```go
// Bounded set
set := ids.NewBoundedSet(10) // Max 10 elements
set.Add(id1, id2, id3)

// Operations
if set.Contains(id1) {
    // id1 is in the set
}

// Clear if over threshold
set.ClearIfSize(8) // Clear if size >= 8
```

## Working with Different ID Types

### Chain IDs

```go
// Platform Chain
platformChainID := ids.Empty

// Contract chains
xChainID, _ := ids.FromString("2JVSBoinj9C2J33VntvzYtVJNZdN2NKiwwKjcumHUWEb5DbBrm")
cChainID, _ := ids.FromString("E1Cjwns27F8vLXbdqg7JdsHuwjNty5mMwVg7CgEXhhJVUmhp8")
```

### Generating Compatible IDs

```go
// Generate Ethereum-compatible address
privKey, _ := secp256k1.NewPrivateKey()
pubKey := privKey.PublicKey()
ethAddress := pubKey.Address()
shortID := ids.ShortID(ethAddress)
```

## Performance Considerations

1. **String Conversion**: Cache string representations if used frequently
2. **Comparison**: Direct byte comparison is fastest
3. **Hashing**: IDs can be used as map keys efficiently
4. **Serialization**: Use raw bytes for storage, strings for display

## Best Practices

1. **Type Safety**: Use specific ID types (NodeID vs ID) to prevent errors
2. **Validation**: Always validate IDs from external sources
3. **Encoding**: Use CB58 for user-facing, hex for debugging
4. **Prefixes**: Include chain prefixes for cross-chain IDs
5. **Error Handling**: Check for Empty ID before operations

## Examples

### Creating a Transaction ID

```go
// Transaction struct
tx := &Transaction{
    BaseTx: BaseTx{
        NetworkID:    1,
        BlockchainID: chainID,
        Outs:         outputs,
        Ins:          inputs,
    },
}

// Serialize
txBytes, err := Codec.Marshal(tx)
if err != nil {
    return err
}

// Generate ID
txID := ids.ID(hashing.ComputeHash256Array(txBytes))
```

### Working with Aliases

```go
aliaser := ids.NewAliaser()

// Register blockchain aliases
aliaser.Alias(xChainID, "X")
aliaser.Alias(cChainID, "C")
aliaser.Alias(platformChainID, "P")

// Parse with alias
chainID, err := aliaser.Parse("X")
```

## Testing

Run tests:

```bash
# All tests
go test ./...

# With race detection
go test -race ./...

# Benchmarks
go test -bench=. ./...
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../CONTRIBUTING.md).

## License

This project is licensed under the BSD 3-Clause License. See the [LICENSE](../LICENSE) file for details.

## References

- [CB58 Encoding](https://docs.lux.network/specs/cryptographic-primitives#cb58)
- [Lux Network IDs](https://docs.lux.network/specs/platform-chain-blocks#id-generation)
- [Node Identity](https://docs.lux.network/nodes/maintain/node-identity)