// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"
)

// LogFormat represents the format of log output.
type LogFormat int

const (
	// Plain is plain text format.
	Plain LogFormat = iota
	// JSON is JSON format.
	JSON
	// Auto detects terminal and uses colors if appropriate.
	Auto
	// Colors forces color output.
	Colors
)

// RotatingWriterConfig configures a rotating log file writer.
type RotatingWriterConfig struct {
	Directory string // Directory to write log files
	MaxSize   int    // Maximum size in megabytes before rotating
	MaxFiles  int    // Maximum number of old log files to retain
	MaxAge    int    // Maximum number of days to retain old log files
	Compress  bool   // Whether to compress old log files
}

// Config represents the logging configuration.
type Config struct {
	RotatingWriterConfig

	LogLevel                Level
	DisplayLevel            Level
	LogFormat               LogFormat
	DisableWriterDisplaying bool
}

// Factory creates loggers with shared configuration.
type Factory interface {
	// Make creates a new logger with the given name.
	Make(name string) (Logger, error)

	// MakeChain creates a logger for a blockchain with the given alias.
	MakeChain(alias string) (Logger, error)

	// MakeChainAndIndex creates loggers for a blockchain and its indexer.
	MakeChainAndIndex(alias string, index string) (Logger, Logger, error)

	// SetLogLevel sets the log level for a named logger.
	SetLogLevel(name string, level Level)

	// SetDisplayLevel sets the display level for a named logger.
	SetDisplayLevel(name string, level Level)

	// GetLogLevel returns the log level for a named logger.
	GetLogLevel(name string) (Level, error)

	// GetDisplayLevel returns the display level for a named logger.
	GetDisplayLevel(name string) (Level, error)

	// Close closes all log files.
	Close()
}

// factory implements Factory.
type factory struct {
	config  Config
	loggers map[string]*factoryLogger
	writers map[string]*lumberjack.Logger
	mu      sync.RWMutex
	closed  bool
}

// factoryLogger wraps a Logger with factory-managed level controls.
type factoryLogger struct {
	Logger              // current logger with level applied
	baseLogger   Logger // base logger without level (for SetLogLevel)
	level        Level
	displayLevel Level
	name         string
	factory      *factory
}

// NewFactory creates a new logger factory with default configuration.
func NewFactory() Factory {
	return NewFactoryWithConfig(Config{
		LogLevel:     InfoLevel,
		DisplayLevel: WarnLevel,
	})
}

// NewFactoryWithConfig creates a new logger factory with the given configuration.
func NewFactoryWithConfig(config Config) Factory {
	return &factory{
		config:  config,
		loggers: make(map[string]*factoryLogger),
		writers: make(map[string]*lumberjack.Logger),
	}
}

// Make creates a new logger with the given name.
func (f *factory) Make(name string) (Logger, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return Noop(), nil
	}

	// Return existing logger if already created (reflects any SetLogLevel changes)
	if l, exists := f.loggers[name]; exists {
		return l.Logger, nil
	}

	// Create writers
	var writers []io.Writer

	// Add file writer if directory is configured
	if f.config.Directory != "" {
		if err := os.MkdirAll(f.config.Directory, 0o755); err != nil {
			return Noop(), err
		}

		lj := &lumberjack.Logger{
			Filename:   filepath.Join(f.config.Directory, name+".log"),
			MaxSize:    f.config.MaxSize,
			MaxBackups: f.config.MaxFiles,
			MaxAge:     f.config.MaxAge,
			Compress:   f.config.Compress,
		}
		if lj.MaxSize == 0 {
			lj.MaxSize = 100 // 100 MB default
		}
		if lj.MaxBackups == 0 {
			lj.MaxBackups = 5 // 5 files default
		}
		f.writers[name] = lj
		writers = append(writers, lj)
	}

	// Add console writer if display is enabled
	if !f.config.DisableWriterDisplaying {
		switch f.config.LogFormat {
		case JSON:
			writers = append(writers, os.Stderr)
		case Colors, Auto:
			writers = append(writers, NewConsoleWriter(func(w *ConsoleWriter) {
				w.Out = os.Stderr
				w.NoColor = false
			}))
		default:
			writers = append(writers, NewConsoleWriter(func(w *ConsoleWriter) {
				w.Out = os.Stderr
				w.NoColor = true
			}))
		}
	}

	// Create multi-writer
	var w io.Writer
	if len(writers) == 0 {
		return Noop(), nil
	} else if len(writers) == 1 {
		w = writers[0]
	} else {
		w = io.MultiWriter(writers...)
	}

	// Create logger - store base logger separately so SetLogLevel can recreate with new level
	baseLogger := NewWriter(w).With().Timestamp().Str("logger", name).Logger()
	logger := baseLogger.Level(f.config.LogLevel)

	fl := &factoryLogger{
		Logger:       logger,
		baseLogger:   baseLogger,
		level:        f.config.LogLevel,
		displayLevel: f.config.DisplayLevel,
		name:         name,
		factory:      f,
	}
	f.loggers[name] = fl

	return fl.Logger, nil
}

// MakeChain creates a logger for a blockchain.
func (f *factory) MakeChain(alias string) (Logger, error) {
	return f.Make("chain." + alias)
}

// MakeChainAndIndex creates loggers for a blockchain and its indexer.
func (f *factory) MakeChainAndIndex(alias string, index string) (Logger, Logger, error) {
	chainLogger, err := f.MakeChain(alias)
	if err != nil {
		return Noop(), Noop(), err
	}
	indexLogger, err := f.Make("index." + alias + "." + index)
	if err != nil {
		return Noop(), Noop(), err
	}
	return chainLogger, indexLogger, nil
}

// SetLogLevel sets the log level for a named logger.
func (f *factory) SetLogLevel(name string, level Level) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if l, exists := f.loggers[name]; exists {
		l.level = level
		// Recreate logger with new level using the base logger
		if l.baseLogger != nil {
			l.Logger = l.baseLogger.Level(level)
		}
	}
}

// SetDisplayLevel sets the display level for a named logger.
func (f *factory) SetDisplayLevel(name string, level Level) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if l, exists := f.loggers[name]; exists {
		l.displayLevel = level
	}
}

// GetLogLevel returns the log level for a named logger.
func (f *factory) GetLogLevel(name string) (Level, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if l, exists := f.loggers[name]; exists {
		return l.level, nil
	}
	return InfoLevel, nil
}

// GetDisplayLevel returns the display level for a named logger.
func (f *factory) GetDisplayLevel(name string) (Level, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if l, exists := f.loggers[name]; exists {
		return l.displayLevel, nil
	}
	return WarnLevel, nil
}

// Close closes all log files.
func (f *factory) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.closed = true
	for _, w := range f.writers {
		_ = w.Close()
	}
}

// NoLog is a no-op logger for use in tests or when logging is disabled.
type NoLog struct{}

func (NoLog) Output(io.Writer) Logger           { return Noop() }
func (NoLog) With() Context                     { return Context{} }
func (NoLog) Level(Level) Logger                { return Noop() }
func (NoLog) GetLevel() Level                   { return Disabled }
func (NoLog) New(...interface{}) Logger         { return Noop() }
func (NoLog) Sample(Sampler) Logger             { return Noop() }
func (NoLog) Hook(...Hook) Logger               { return Noop() }
func (NoLog) Trace(string, ...interface{})      {}
func (NoLog) Debug(string, ...interface{})      {}
func (NoLog) Info(string, ...interface{})       {}
func (NoLog) Warn(string, ...interface{})       {}
func (NoLog) Error(string, ...interface{})      {}
func (NoLog) Fatal(string, ...interface{})      {}
func (NoLog) Panic(string, ...interface{})      {}
func (NoLog) Crit(string, ...interface{})       {}
func (NoLog) Verbo(string, ...interface{})      {}
func (NoLog) Log(Level, string, ...interface{}) {}
func (NoLog) TraceEvent() *Event                { return nil }
func (NoLog) DebugEvent() *Event                { return nil }
func (NoLog) InfoEvent() *Event                 { return nil }
func (NoLog) WarnEvent() *Event                 { return nil }
func (NoLog) ErrorEvent() *Event                { return nil }
func (NoLog) FatalEvent() *Event                { return nil }
func (NoLog) PanicEvent() *Event                { return nil }
func (NoLog) Err(error) *Event                  { return nil }
func (NoLog) WithLevel(Level) *Event            { return nil }
func (NoLog) LogEvent() *Event                  { return nil }
func (NoLog) Print(...interface{})              {}
func (NoLog) Printf(string, ...interface{})     {}
func (NoLog) Write(p []byte) (int, error)       { return len(p), nil }
func (NoLog) SetLogLevel(string) error          { return nil }
func (NoLog) RecoverAndPanic(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
	}()
	fn()
}
func (NoLog) IsZero() bool                             { return true }
func (NoLog) Enabled(context.Context, slog.Level) bool { return false }

// ToLevel parses a level string and returns the corresponding Level.
func ToLevel(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "trace", "trce", "verbo", "verbose":
		return TraceLevel, nil
	case "debug", "dbug":
		return DebugLevel, nil
	case "info":
		return InfoLevel, nil
	case "warn", "warning":
		return WarnLevel, nil
	case "error", "eror":
		return ErrorLevel, nil
	case "fatal":
		return FatalLevel, nil
	case "panic":
		return PanicLevel, nil
	case "disabled", "off":
		return Disabled, nil
	default:
		return NoLevel, fmt.Errorf("unknown log level: %s", s)
	}
}

// ToFormat parses a format string and returns the corresponding LogFormat.
// The fd parameter is reserved for future use (e.g., terminal detection).
func ToFormat(s string, fd uintptr) (LogFormat, error) {
	switch strings.ToLower(s) {
	case "plain", "text", "":
		return Plain, nil
	case "json":
		return JSON, nil
	case "auto":
		return Auto, nil
	case "colors", "color":
		return Colors, nil
	default:
		return Plain, fmt.Errorf("unknown log format: %s", s)
	}
}

// RegisterInternalPackages registers packages as internal for caller tracking.
// When a log call is made from an internal package, the caller tracking will
// skip it and show the actual calling code location.
var internalPackages = make(map[string]bool)
var internalPackagesMu sync.RWMutex

func RegisterInternalPackages(packages ...string) {
	internalPackagesMu.Lock()
	defer internalPackagesMu.Unlock()
	for _, pkg := range packages {
		internalPackages[pkg] = true
	}
}

func IsInternalPackage(pkg string) bool {
	internalPackagesMu.RLock()
	defer internalPackagesMu.RUnlock()
	return internalPackages[pkg]
}
