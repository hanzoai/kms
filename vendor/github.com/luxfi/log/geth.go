// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package log

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"
)

// FormatLogfmtUint64 formats a uint64 as a compact logfmt string.
func FormatLogfmtUint64(n uint64) string {
	return strconv.FormatUint(n, 10)
}

// Level aliases for geth compatibility have been moved to slog.go
// to avoid duplicate declarations.

// Field represents a key-value pair for geth-style structured logging.
// This provides compatibility with go-ethereum's logging patterns.
type Field struct {
	Key   string
	Value interface{}
}

// Field constructors for geth-style logging
func String(key, val string) Field                 { return Field{Key: key, Value: val} }
func Stringer(key string, val fmt.Stringer) Field  { return Field{Key: key, Value: val} }
func Int(key string, val int) Field                { return Field{Key: key, Value: val} }
func Int8(key string, val int8) Field              { return Field{Key: key, Value: val} }
func Int16(key string, val int16) Field            { return Field{Key: key, Value: val} }
func Int32(key string, val int32) Field            { return Field{Key: key, Value: val} }
func Int64(key string, val int64) Field            { return Field{Key: key, Value: val} }
func Uint(key string, val uint) Field              { return Field{Key: key, Value: val} }
func Uint8(key string, val uint8) Field            { return Field{Key: key, Value: val} }
func Uint16(key string, val uint16) Field          { return Field{Key: key, Value: val} }
func Uint32(key string, val uint32) Field          { return Field{Key: key, Value: val} }
func Uint64(key string, val uint64) Field          { return Field{Key: key, Value: val} }
func Float32(key string, val float32) Field        { return Field{Key: key, Value: val} }
func Float64(key string, val float64) Field        { return Field{Key: key, Value: val} }
func Bool(key string, val bool) Field              { return Field{Key: key, Value: val} }
func Duration(key string, val time.Duration) Field { return Field{Key: key, Value: val} }
func Time(key string, val time.Time) Field         { return Field{Key: key, Value: val} }
func Err(err error) Field                          { return Field{Key: ErrorFieldName, Value: err} }
func NamedErr(key string, err error) Field         { return Field{Key: key, Value: err} }
func Any(key string, val interface{}) Field        { return Field{Key: key, Value: val} }
func Binary(key string, val []byte) Field          { return Field{Key: key, Value: val} }
func ByteString(key string, val []byte) Field      { return Field{Key: key, Value: string(val)} }

// Slice field constructors
func Strings(key string, val []string) Field          { return Field{Key: key, Value: val} }
func Ints(key string, val []int) Field                { return Field{Key: key, Value: val} }
func Int64s(key string, val []int64) Field            { return Field{Key: key, Value: val} }
func Uint64s(key string, val []uint64) Field          { return Field{Key: key, Value: val} }
func Float64s(key string, val []float64) Field        { return Field{Key: key, Value: val} }
func Bools(key string, val []bool) Field              { return Field{Key: key, Value: val} }
func Durations(key string, val []time.Duration) Field { return Field{Key: key, Value: val} }
func Times(key string, val []time.Time) Field         { return Field{Key: key, Value: val} }

// Short-form aliases (matching chaining API style)
func Str(key, val string) Field               { return String(key, val) }
func Dur(key string, val time.Duration) Field { return Duration(key, val) }
func AnErr(key string, err error) Field       { return NamedErr(key, err) }

// Stack returns a Field with the current stack trace.
func Stack(key string) Field {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return Field{Key: key, Value: string(buf[:n])}
}

// defaultLogger is the global logger for geth-style functions.
// Default level is Info — debug/trace messages are suppressed unless
// explicitly enabled via SetDefault() or SetGlobalLevel(DebugLevel).
// This prevents dependency init() functions from spamming stderr
// with debug output before the application configures logging.
var defaultLogger = NewWriter(os.Stderr).With().Timestamp().Logger().Level(InfoLevel)

// SetDefault sets the default logger for geth-style functions
func SetDefault(l Logger) {
	defaultLogger = l
}

// Root returns the default logger
func Root() Logger {
	return defaultLogger
}

// Default returns the default logger (alias for Root)
func Default() Logger {
	return defaultLogger
}

// UserString returns a Field for user-provided string values.
// This is the same as String but semantically indicates user input.
func UserString(key, val string) Field { return String(key, val) }

// Reflect returns a Field that uses reflection for complex types.
func Reflect(key string, val interface{}) Field { return Any(key, val) }

// applyField applies a single Field to an Event.
func applyField(e *Event, f Field) *Event {
	switch v := f.Value.(type) {
	case string:
		return e.Str(f.Key, v)
	case int:
		return e.Int(f.Key, v)
	case int64:
		return e.Int64(f.Key, v)
	case uint:
		return e.Uint(f.Key, v)
	case uint64:
		return e.Uint64(f.Key, v)
	case float64:
		return e.Float64(f.Key, v)
	case bool:
		return e.Bool(f.Key, v)
	case time.Duration:
		return e.Dur(f.Key, v)
	case time.Time:
		return e.Time(f.Key, v)
	case error:
		if !isNilValue(v) {
			return e.AnErr(f.Key, v)
		}
		return e
	case []byte:
		return e.Bytes(f.Key, v)
	case fmt.Stringer:
		if !isNilValue(v) {
			return e.Str(f.Key, v.String())
		}
		return e
	default:
		return e.Interface(f.Key, f.Value)
	}
}

// applyContext applies geth-style key-value pairs to an Event.
// Accepts alternating key-value pairs: key1, val1, key2, val2, ...
// Also supports Field values directly (log.UserString, log.Reflect, etc.)
func applyContext(e *Event, ctx []interface{}) *Event {
	if e == nil {
		return nil
	}
	for i := 0; i < len(ctx); {
		// Check if this is a Field at key position (log.UserString, log.Reflect, etc.)
		if f, ok := ctx[i].(Field); ok {
			e = applyField(e, f)
			i++
			continue
		}

		// Otherwise, expect key-value pair
		if i+1 >= len(ctx) {
			break
		}
		key, ok := ctx[i].(string)
		if !ok {
			i++
			continue
		}
		val := ctx[i+1]
		i += 2
		switch v := val.(type) {
		case string:
			e = e.Str(key, v)
		case int:
			e = e.Int(key, v)
		case int8:
			e = e.Int8(key, v)
		case int16:
			e = e.Int16(key, v)
		case int32:
			e = e.Int32(key, v)
		case int64:
			e = e.Int64(key, v)
		case uint:
			e = e.Uint(key, v)
		case uint8:
			e = e.Uint8(key, v)
		case uint16:
			e = e.Uint16(key, v)
		case uint32:
			e = e.Uint32(key, v)
		case uint64:
			e = e.Uint64(key, v)
		case float32:
			e = e.Float32(key, v)
		case float64:
			e = e.Float64(key, v)
		case bool:
			e = e.Bool(key, v)
		case time.Duration:
			e = e.Dur(key, v)
		case time.Time:
			e = e.Time(key, v)
		case error:
			if !isNilValue(v) {
				e = e.AnErr(key, v)
			}
		case []byte:
			e = e.Bytes(key, v)
		case fmt.Stringer:
			if !isNilValue(v) {
				e = e.Str(key, v.String())
			}
		case Field:
			// Support Field type in value position for backward compatibility
			e = applyField(e, v)
		default:
			e = e.Interface(key, v)
		}
	}
	return e
}

// Geth-style global logging functions
// These accept alternating key-value pairs: msg, key1, val1, key2, val2, ...

// Trace logs at trace level with geth-style context
func Trace(msg string, ctx ...interface{}) {
	applyContext(defaultLogger.TraceEvent(), ctx).Msg(msg)
}

// Debug logs at debug level with geth-style context
func Debug(msg string, ctx ...interface{}) {
	applyContext(defaultLogger.DebugEvent(), ctx).Msg(msg)
}

// Info logs at info level with geth-style context
func Info(msg string, ctx ...interface{}) {
	applyContext(defaultLogger.InfoEvent(), ctx).Msg(msg)
}

// Warn logs at warn level with geth-style context
func Warn(msg string, ctx ...interface{}) {
	applyContext(defaultLogger.WarnEvent(), ctx).Msg(msg)
}

// Error logs at error level with geth-style context
func Error(msg string, ctx ...interface{}) {
	applyContext(defaultLogger.ErrorEvent(), ctx).Msg(msg)
}

// Fatal logs at fatal level with geth-style context and exits
func Fatal(msg string, ctx ...interface{}) {
	applyContext(defaultLogger.FatalEvent(), ctx).Msg(msg)
}

// Crit is an alias for Fatal (geth compatibility)
func Crit(msg string, ctx ...interface{}) {
	Fatal(msg, ctx...)
}

// Log logs at the specified level with geth-style context
func Log(level Level, msg string, ctx ...interface{}) {
	applyContext(defaultLogger.WithLevel(level), ctx).Msg(msg)
}

// NewNoOpLogger returns a disabled logger.
func NewNoOpLogger() Logger {
	return Noop()
}

// NewTestLogger returns a logger suitable for testing.
// If a level is provided, the logger is set to that level.
func NewTestLogger(level ...Level) Logger {
	l := NewWriter(os.Stderr).With().Timestamp().Logger()
	if len(level) > 0 {
		l = l.Level(level[0])
	}
	return l
}
