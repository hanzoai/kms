// Package log provides a high-performance structured logging library.
//
// This package supports two logging styles:
//
// 1. Geth-style variadic logging (recommended for compatibility):
//
//	log := log.New("component", "myapp")
//	log.Info("server started", "port", 8080)
//	log.Debug("processing request", "id", reqID, "user", userID)
//
// 2. Method chaining (zero-allocation):
//
//	log := log.NewWriter(os.Stderr).With().Str("component", "myapp").Logger()
//	log.Info().Str("port", "8080").Msg("server started")
//
// Both styles can be mixed. The geth-style methods internally use the
// zero-allocation Event system for high performance.
package log

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// ErrUnknownLevel is returned when parsing an unknown log level string.
var ErrUnknownLevel = errors.New("unknown log level")

// Level defines log levels.
type Level int8

const (
	// DebugLevel defines debug log level.
	DebugLevel Level = iota
	// InfoLevel defines info log level.
	InfoLevel
	// WarnLevel defines warn log level.
	WarnLevel
	// ErrorLevel defines error log level.
	ErrorLevel
	// FatalLevel defines fatal log level.
	FatalLevel
	// PanicLevel defines panic log level.
	PanicLevel
	// NoLevel defines an absent log level.
	NoLevel
	// Disabled disables the logger.
	Disabled

	// TraceLevel defines trace level.
	TraceLevel Level = -1
	// Values less than TraceLevel are handled as numbers.
)

func (l Level) String() string {
	switch l {
	case TraceLevel:
		return LevelTraceValue
	case DebugLevel:
		return LevelDebugValue
	case InfoLevel:
		return LevelInfoValue
	case WarnLevel:
		return LevelWarnValue
	case ErrorLevel:
		return LevelErrorValue
	case FatalLevel:
		return LevelFatalValue
	case PanicLevel:
		return LevelPanicValue
	case Disabled:
		return "disabled"
	case NoLevel:
		return ""
	}
	return strconv.Itoa(int(l))
}

// ParseLevel converts a level string into a logger Level value.
func ParseLevel(levelStr string) (Level, error) {
	switch {
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(TraceLevel)):
		return TraceLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(DebugLevel)):
		return DebugLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(InfoLevel)):
		return InfoLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(WarnLevel)):
		return WarnLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(ErrorLevel)):
		return ErrorLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(FatalLevel)):
		return FatalLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(PanicLevel)):
		return PanicLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(Disabled)):
		return Disabled, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(NoLevel)):
		return NoLevel, nil
	}
	i, err := strconv.Atoi(levelStr)
	if err != nil {
		return NoLevel, fmt.Errorf("Unknown Level String: '%s', defaulting to NoLevel", levelStr)
	}
	if i > 127 || i < -128 {
		return NoLevel, fmt.Errorf("Out-Of-Bounds Level: '%d', defaulting to NoLevel", i)
	}
	return Level(i), nil
}

// UnmarshalText implements encoding.TextUnmarshaler
func (l *Level) UnmarshalText(text []byte) error {
	if l == nil {
		return errors.New("can't unmarshal a nil *Level")
	}
	var err error
	*l, err = ParseLevel(string(text))
	return err
}

// MarshalText implements encoding.TextMarshaler
func (l Level) MarshalText() ([]byte, error) {
	return []byte(LevelFieldMarshalFunc(l)), nil
}

// =============================================================================
// Logger Interface - the public API
// =============================================================================

// Logger is the primary logging interface. All logging implementations
// satisfy this interface. Use == nil to check for uninitialized loggers.
type Logger interface {
	// Geth-style variadic logging methods
	Trace(msg string, ctx ...interface{})
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Warn(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
	Fatal(msg string, ctx ...interface{})
	Panic(msg string, ctx ...interface{})
	Crit(msg string, ctx ...interface{})
	Verbo(msg string, ctx ...interface{})
	Log(level Level, msg string, ctx ...interface{})

	// Context/child loggers
	With() Context
	New(ctx ...interface{}) Logger
	Output(w io.Writer) Logger

	// Level control
	Level(lvl Level) Logger
	GetLevel() Level
	Enabled(ctx context.Context, level slog.Level) bool

	// Zero-allocation event-based logging
	TraceEvent() *Event
	DebugEvent() *Event
	InfoEvent() *Event
	WarnEvent() *Event
	ErrorEvent() *Event
	FatalEvent() *Event
	PanicEvent() *Event
	Err(err error) *Event
	WithLevel(level Level) *Event
	LogEvent() *Event

	// Utilities
	Sample(s Sampler) Logger
	Hook(hooks ...Hook) Logger
	Print(v ...interface{})
	Printf(format string, v ...interface{})
	Write(p []byte) (n int, err error)

	// Configuration
	SetLogLevel(level string) error
	RecoverAndPanic(fn func())

	// IsZero returns true if the logger is disabled or uninitialized.
	IsZero() bool
}

// noopSingleton is the internal no-op logger instance.
var noopSingleton Logger = &noopLogger{}

// Noop returns a disabled logger. Use this for optional logger parameters.
// Example: func DoWork(logger log.Logger) { if logger == nil { logger = log.Noop() } }
func Noop() Logger {
	return noopSingleton
}

// =============================================================================
// Constructors
// =============================================================================

// New creates a new logger with optional context key-value pairs.
// Usage: log.New("component", "myapp", "version", "1.0")
func New(ctx ...interface{}) Logger {
	l := newLogger(os.Stderr).With().Timestamp().Logger()
	if len(ctx) > 0 {
		return l.With().Fields(ctx).Logger()
	}
	return l
}

// NewWriter creates a logger with a specific output writer.
func NewWriter(w io.Writer) Logger {
	return newLogger(w)
}

// InitLogger creates a new logger with the specified configuration.
// This is used by EVM to initialize the VM logger.
func InitLogger(chainAlias string, logLevel string, jsonFormat bool, writer io.Writer) (Logger, error) {
	level, err := ParseLevel(logLevel)
	if err != nil {
		level = InfoLevel
	}
	l := newLogger(writer).With().Timestamp().Str("chain", chainAlias).Logger()
	return l.Level(level), nil
}

// =============================================================================
// logger implementation (private)
// =============================================================================

// logger is the internal implementation of Logger interface.
type logger struct {
	w       LevelWriter
	level   Level
	sampler Sampler
	context []byte
	hooks   []Hook
	stack   bool
	ctx     context.Context
}

// newLogger creates a new logger with the given writer.
func newLogger(w io.Writer) *logger {
	if w == nil {
		w = io.Discard
	}
	lw, ok := w.(LevelWriter)
	if !ok {
		lw = LevelWriterAdapter{w}
	}
	return &logger{w: lw, level: TraceLevel}
}

// Output duplicates the current logger and sets w as its output.
func (l *logger) Output(w io.Writer) Logger {
	l2 := newLogger(w)
	l2.level = l.level
	l2.sampler = l.sampler
	l2.stack = l.stack
	if len(l.hooks) > 0 {
		l2.hooks = append(l2.hooks, l.hooks...)
	}
	if l.context != nil {
		l2.context = make([]byte, len(l.context), cap(l.context))
		copy(l2.context, l.context)
	}
	return l2
}

// With creates a child logger with the field added to its context.
func (l *logger) With() Context {
	context := l.context
	newCtx := make([]byte, 0, 500)
	if context != nil {
		newCtx = append(newCtx, context...)
	} else {
		newCtx = enc.AppendBeginMarker(newCtx)
	}
	return Context{&logger{
		w:       l.w,
		level:   l.level,
		sampler: l.sampler,
		context: newCtx,
		hooks:   l.hooks,
		stack:   l.stack,
		ctx:     l.ctx,
	}}
}

// Level creates a child logger with the minimum accepted level set to level.
func (l *logger) Level(lvl Level) Logger {
	return &logger{
		w:       l.w,
		level:   lvl,
		sampler: l.sampler,
		context: l.context,
		hooks:   l.hooks,
		stack:   l.stack,
		ctx:     l.ctx,
	}
}

// GetLevel returns the current Level of l.
func (l *logger) GetLevel() Level {
	return l.level
}

// IsZero returns true if the logger is disabled or uninitialized.
func (l *logger) IsZero() bool {
	return l == nil || l.w == nil
}

// New creates a child logger with the given context key-value pairs.
func (l *logger) New(ctx ...interface{}) Logger {
	if len(ctx) > 0 {
		return l.With().Fields(ctx).Logger()
	}
	return l
}

// Enabled checks if the given level is enabled for this logger.
func (l *logger) Enabled(ctx context.Context, level slog.Level) bool {
	var internalLevel Level
	switch {
	case level <= slogLevelTrace:
		internalLevel = TraceLevel
	case level <= slog.LevelDebug:
		internalLevel = DebugLevel
	case level <= slog.LevelInfo:
		internalLevel = InfoLevel
	case level <= slog.LevelWarn:
		internalLevel = WarnLevel
	case level <= slog.LevelError:
		internalLevel = ErrorLevel
	default:
		internalLevel = FatalLevel
	}
	return l.should(internalLevel)
}

// Sample returns a logger with the s sampler.
func (l *logger) Sample(s Sampler) Logger {
	return &logger{
		w:       l.w,
		level:   l.level,
		sampler: s,
		context: l.context,
		hooks:   l.hooks,
		stack:   l.stack,
		ctx:     l.ctx,
	}
}

// Hook returns a logger with the h Hook (satisfies Logger interface).
func (l *logger) Hook(hooks ...Hook) Logger {
	return l.hook(hooks...)
}

// hook is the internal method that returns *logger for context chaining.
func (l *logger) hook(hooks ...Hook) *logger {
	if len(hooks) == 0 {
		return l
	}
	newHooks := make([]Hook, len(l.hooks), len(l.hooks)+len(hooks))
	copy(newHooks, l.hooks)
	return &logger{
		w:       l.w,
		level:   l.level,
		sampler: l.sampler,
		context: l.context,
		hooks:   append(newHooks, hooks...),
		stack:   l.stack,
		ctx:     l.ctx,
	}
}

// --- Geth-style variadic logging methods ---

func (l *logger) Trace(msg string, ctx ...interface{}) {
	if e := l.newEvent(TraceLevel, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

func (l *logger) Debug(msg string, ctx ...interface{}) {
	if e := l.newEvent(DebugLevel, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

func (l *logger) Info(msg string, ctx ...interface{}) {
	if e := l.newEvent(InfoLevel, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

func (l *logger) Warn(msg string, ctx ...interface{}) {
	if e := l.newEvent(WarnLevel, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

func (l *logger) Error(msg string, ctx ...interface{}) {
	if e := l.newEvent(ErrorLevel, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

func (l *logger) Fatal(msg string, ctx ...interface{}) {
	if e := l.newEvent(FatalLevel, func(msg string) {
		if closer, ok := l.w.(io.Closer); ok {
			closer.Close()
		}
		os.Exit(1)
	}); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

func (l *logger) Panic(msg string, ctx ...interface{}) {
	if e := l.newEvent(PanicLevel, func(msg string) { panic(msg) }); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

func (l *logger) Crit(msg string, ctx ...interface{}) {
	l.Fatal(msg, ctx...)
}

func (l *logger) Verbo(msg string, ctx ...interface{}) {
	l.Trace(msg, ctx...)
}

func (l *logger) Log(level Level, msg string, ctx ...interface{}) {
	if e := l.newEvent(level, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

// --- Method chaining API (zero-allocation) ---

func (l *logger) TraceEvent() *Event {
	return l.newEvent(TraceLevel, nil)
}

func (l *logger) DebugEvent() *Event {
	return l.newEvent(DebugLevel, nil)
}

func (l *logger) InfoEvent() *Event {
	return l.newEvent(InfoLevel, nil)
}

func (l *logger) WarnEvent() *Event {
	return l.newEvent(WarnLevel, nil)
}

func (l *logger) ErrorEvent() *Event {
	return l.newEvent(ErrorLevel, nil)
}

func (l *logger) FatalEvent() *Event {
	return l.newEvent(FatalLevel, func(msg string) {
		if closer, ok := l.w.(io.Closer); ok {
			closer.Close()
		}
		os.Exit(1)
	})
}

func (l *logger) PanicEvent() *Event {
	return l.newEvent(PanicLevel, func(msg string) { panic(msg) })
}

func (l *logger) Err(err error) *Event {
	if err != nil {
		return l.ErrorEvent().Err(err)
	}
	return l.InfoEvent()
}

func (l *logger) WithLevel(level Level) *Event {
	switch level {
	case TraceLevel:
		return l.TraceEvent()
	case DebugLevel:
		return l.DebugEvent()
	case InfoLevel:
		return l.InfoEvent()
	case WarnLevel:
		return l.WarnEvent()
	case ErrorLevel:
		return l.ErrorEvent()
	case FatalLevel:
		return l.newEvent(FatalLevel, nil)
	case PanicLevel:
		return l.newEvent(PanicLevel, nil)
	case NoLevel:
		return l.LogEvent()
	case Disabled:
		return nil
	default:
		return l.newEvent(level, nil)
	}
}

func (l *logger) LogEvent() *Event {
	return l.newEvent(NoLevel, nil)
}

func (l *logger) Print(v ...interface{}) {
	if e := l.DebugEvent(); e.Enabled() {
		e.CallerSkipFrame(1).Msg(fmt.Sprint(v...))
	}
}

func (l *logger) Printf(format string, v ...interface{}) {
	if e := l.DebugEvent(); e.Enabled() {
		e.CallerSkipFrame(1).Msg(fmt.Sprintf(format, v...))
	}
}

func (l *logger) Write(p []byte) (n int, err error) {
	n = len(p)
	if n > 0 && p[n-1] == '\n' {
		p = p[0 : n-1]
	}
	l.LogEvent().CallerSkipFrame(1).Msg(string(p))
	return
}

// SetLogLevel sets the log level from a string.
func (l *logger) SetLogLevel(level string) error {
	lvl, err := ParseLevel(level)
	if err != nil {
		return err
	}
	SetGlobalLevel(lvl)
	return nil
}

// RecoverAndPanic runs the function and recovers from any panic, logging it before re-panicking.
func (l *logger) RecoverAndPanic(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			l.Error("panic recovered", "panic", r)
			panic(r)
		}
	}()
	fn()
}

func (l *logger) newEvent(level Level, done func(string)) *Event {
	enabled := l.should(level)
	if !enabled {
		if done != nil {
			done("")
		}
		return nil
	}
	e := newEvent(l.w, level, l.stack, l.ctx, l.hooks)
	e.done = done
	if level != NoLevel && LevelFieldName != "" {
		e.Str(LevelFieldName, LevelFieldMarshalFunc(level))
	}
	if len(l.context) > 1 {
		e.buf = enc.AppendObjectData(e.buf, l.context)
	}
	return e
}

// scratchEvent creates a temporary event for encoding in Context methods.
// This event is not for logging but for constructing context data.
func (l *logger) scratchEvent() *Event {
	return newEvent(LevelWriterAdapter{io.Discard}, DebugLevel, l.stack, l.ctx, l.hooks)
}

func (l *logger) should(lvl Level) bool {
	if l.w == nil {
		return false
	}
	if lvl < l.level || lvl < GlobalLevel() {
		return false
	}
	if l.sampler != nil && !samplingDisabled() {
		return l.sampler.Sample(lvl)
	}
	return true
}

// =============================================================================
// noopLogger - disabled logger implementation
// =============================================================================

type noopLogger struct{}

func (noopLogger) Trace(string, ...interface{})             {}
func (noopLogger) Debug(string, ...interface{})             {}
func (noopLogger) Info(string, ...interface{})              {}
func (noopLogger) Warn(string, ...interface{})              {}
func (noopLogger) Error(string, ...interface{})             {}
func (noopLogger) Fatal(string, ...interface{})             {}
func (noopLogger) Panic(string, ...interface{})             {}
func (noopLogger) Crit(string, ...interface{})              {}
func (noopLogger) Verbo(string, ...interface{})             {}
func (noopLogger) Log(Level, string, ...interface{})        {}
func (n noopLogger) With() Context                          { return Context{} }
func (n noopLogger) New(...interface{}) Logger              { return n }
func (n noopLogger) Output(io.Writer) Logger                { return n }
func (n noopLogger) Level(Level) Logger                     { return n }
func (noopLogger) GetLevel() Level                          { return Disabled }
func (noopLogger) IsZero() bool                             { return true }
func (noopLogger) Enabled(context.Context, slog.Level) bool { return false }
func (noopLogger) Sample(Sampler) Logger                    { return Noop() }
func (noopLogger) Hook(...Hook) Logger                      { return Noop() }
func (noopLogger) TraceEvent() *Event                       { return nil }
func (noopLogger) DebugEvent() *Event                       { return nil }
func (noopLogger) InfoEvent() *Event                        { return nil }
func (noopLogger) WarnEvent() *Event                        { return nil }
func (noopLogger) ErrorEvent() *Event                       { return nil }
func (noopLogger) FatalEvent() *Event                       { return nil }
func (noopLogger) PanicEvent() *Event                       { return nil }
func (noopLogger) Err(error) *Event                         { return nil }
func (noopLogger) WithLevel(Level) *Event                   { return nil }
func (noopLogger) LogEvent() *Event                         { return nil }
func (noopLogger) Print(...interface{})                     {}
func (noopLogger) Printf(string, ...interface{})            {}
func (noopLogger) Write(p []byte) (int, error)              { return len(p), nil }
func (noopLogger) SetLogLevel(string) error                 { return nil }
func (noopLogger) RecoverAndPanic(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
	}()
	fn()
}
