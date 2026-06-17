# Lux Logger

A high-performance, zero-allocation structured logging library for the Lux ecosystem. Based on [zerolog](https://github.com/rs/zerolog) with additional geth-style API support.

## Features

- **Blazing fast**: ~8ns/op for empty log, zero allocations
- **Zero allocation**: Uses sync.Pool for Event recycling
- **Two logging styles**: Chaining API + traditional API (geth-compatible)
- **Structured logging**: Type-safe field constructors
- **Leveled logging**: Trace, Debug, Info, Warn, Error, Fatal, Panic
- **Contextual fields**: Pre-set fields via `With()`
- **Pretty console output**: Colorized human-readable format
- **Sampling**: Reduce log volume in production
- **Hooks**: Custom processing for log events

## Installation

```bash
go get github.com/luxfi/logger
```

## Quick Start

### Chaining API

```go
import "github.com/luxfi/logger/log"

// Simple logging
log.Info().Msg("hello world")

// With fields
log.Info().
    Str("user", "alice").
    Int("attempt", 3).
    Msg("login successful")

// With timestamp
log.Logger = log.Output(os.Stdout).With().Timestamp().Logger()
```

### Traditional API (geth-compatible)

```go
import "github.com/luxfi/logger"

// Simple logging
logger.Info("hello world")

// With fields
logger.Info("login successful",
    logger.String("user", "alice"),
    logger.Int("attempt", 3),
)

// Error with stack
logger.Error("operation failed", logger.Err(err))
```

## Performance

Zero-allocation design using sync.Pool:

```
BenchmarkLogEmpty-10        161256609     8.443 ns/op    0 B/op   0 allocs/op
BenchmarkLogFields-10        32669988    40.22 ns/op     0 B/op   0 allocs/op
BenchmarkLogFieldType/Str    95961300    11.68 ns/op     0 B/op   0 allocs/op
BenchmarkLogFieldType/Int    89553908    11.75 ns/op     0 B/op   0 allocs/op
BenchmarkLogFieldType/Bool   94231278    12.02 ns/op     0 B/op   0 allocs/op
BenchmarkLogFieldType/Time   69632661    18.13 ns/op     0 B/op   0 allocs/op
```

**Comparison with other loggers:**

| Library | Time | Bytes | Allocs |
|---------|------|-------|--------|
| **luxfi/logger** | 8 ns/op | 0 B/op | 0 allocs/op |
| zerolog | 19 ns/op | 0 B/op | 0 allocs/op |
| zap | 236 ns/op | 0 B/op | 0 allocs/op |
| logrus | 1244 ns/op | 1505 B/op | 27 allocs/op |

## Log Levels

```go
const (
    TraceLevel Level = -1
    DebugLevel Level = 0
    InfoLevel  Level = 1
    WarnLevel  Level = 2
    ErrorLevel Level = 3
    FatalLevel Level = 4
    PanicLevel Level = 5
)
```

### Setting Level

```go
// Global level
logger.SetGlobalLevel(logger.WarnLevel)

// Per-logger level
log := logger.New(os.Stdout).Level(logger.InfoLevel)
```

## Field Types

### Chaining API (on Event)

```go
event.Str("key", "value")
event.Int("key", 42)
event.Float64("key", 3.14)
event.Bool("key", true)
event.Err(err)
event.Time("key", time.Now())
event.Dur("key", time.Second)
event.Interface("key", obj)
event.Bytes("key", []byte{})
event.Strs("key", []string{})
event.Ints("key", []int{})
```

### Traditional API (Field constructors)

```go
logger.String("key", "value")  // or logger.Str("key", "value")
logger.Int("key", 42)
logger.Float64("key", 3.14)
logger.Bool("key", true)
logger.Err(err)
logger.Time("key", time.Now())
logger.Duration("key", time.Second)  // or logger.Dur("key", time.Second)
logger.Any("key", obj)
logger.Binary("key", []byte{})
```

## Context Logger

Pre-set fields for all log messages:

```go
// Chaining API
log := logger.New(os.Stdout).With().
    Str("service", "api").
    Str("version", "1.0.0").
    Logger()

log.Info().Msg("request") // includes service and version

// Traditional API
logger.SetDefault(log)
logger.Info("request") // includes service and version
```

## Pretty Console Output

```go
output := logger.ConsoleWriter{Out: os.Stdout}
log := logger.New(output)

log.Info().Str("foo", "bar").Msg("Hello World")
// Output: 3:04pm INF Hello World foo=bar
```

## Sampling

Reduce log volume:

```go
sampled := log.Sample(&logger.BasicSampler{N: 10})
sampled.Info().Msg("logged every 10 messages")
```

## Hooks

```go
type SeverityHook struct{}

func (h SeverityHook) Run(e *logger.Event, level logger.Level, msg string) {
    if level != logger.NoLevel {
        e.Str("severity", level.String())
    }
}

log := logger.New(os.Stdout).Hook(SeverityHook{})
```

## Sub-packages

- `github.com/luxfi/logger` - Core package with traditional API
- `github.com/luxfi/logger/log` - Global logger with chaining API

## Why not just use zerolog?

1. **Package naming**: `logger` doesn't shadow Go's `log` package
2. **Dual API**: Both zerolog chaining and geth-style traditional logging
3. **Lux ecosystem integration**: Designed for Lux blockchain projects
4. **Performance tuned**: Even faster than upstream zerolog on some benchmarks

## License

See LICENSE file for details.
