// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package log

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
)

// slog.Level constants for slog-based handlers
const (
	levelMaxVerbosity slog.Level = math.MinInt
	slogLevelTrace    slog.Level = -8
	slogLevelDebug               = slog.LevelDebug
	slogLevelInfo                = slog.LevelInfo
	slogLevelWarn                = slog.LevelWarn
	slogLevelError               = slog.LevelError
	slogLevelCrit     slog.Level = 12

	// Exported slog.Level constants for use with Logger.Enabled()
	SlogLevelTrace slog.Level = slogLevelTrace
	SlogLevelDebug            = slogLevelDebug
	SlogLevelInfo             = slogLevelInfo
	SlogLevelWarn             = slogLevelWarn
	SlogLevelError            = slogLevelError
	SlogLevelCrit             = slogLevelCrit
)

// Level aliases for geth/logger compatibility.
// These are logger.Level type (int8) for use with Logger.Enabled().
const (
	LevelTrace Level = TraceLevel
	LevelDebug Level = DebugLevel
	LevelInfo  Level = InfoLevel
	LevelWarn  Level = WarnLevel
	LevelError Level = ErrorLevel
	LevelCrit  Level = FatalLevel

	// Aliases for backward compatibility
	LvlTrace = LevelTrace
	LvlInfo  = LevelInfo
	LvlDebug = LevelDebug
)

const (
	legacyLevelCrit = iota
	legacyLevelError
	legacyLevelWarn
	legacyLevelInfo
	legacyLevelDebug
	legacyLevelTrace
)

const (
	timeFormat        = "2006-01-02T15:04:05-0700"
	floatFormat       = 'f'
	termMsgJust       = 40
	termCtxMaxPadding = 40
)

var spaces = []byte("                                        ")

// SlogLogger is a Logger interface that wraps slog for geth compatibility.
type SlogLogger interface {
	With(ctx ...interface{}) SlogLogger
	New(ctx ...interface{}) SlogLogger
	Log(level slog.Level, msg string, ctx ...interface{})
	Trace(msg string, ctx ...interface{})
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Warn(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
	Crit(msg string, ctx ...interface{})
	Write(level slog.Level, msg string, attrs ...interface{})
	Enabled(ctx context.Context, level slog.Level) bool
	Handler() slog.Handler
}

type slogLogger struct {
	inner *slog.Logger
}

var defaultSlogLogger atomic.Pointer[slogLogger]

func init() {
	defaultSlogLogger.Store(&slogLogger{inner: slog.Default()})
}

// SlogRoot returns the root slog-based logger.
func SlogRoot() SlogLogger {
	return defaultSlogLogger.Load()
}

// SetSlogDefault sets the default slog-based logger.
func SetSlogDefault(l SlogLogger) {
	if lg, ok := l.(*slogLogger); ok {
		defaultSlogLogger.Store(lg)
		slog.SetDefault(lg.inner)
	}
}

// NewLogger creates a new SlogLogger with the given handler.
func NewLogger(h slog.Handler) SlogLogger {
	return &slogLogger{inner: slog.New(h)}
}

// NewLoggerFromHandler creates a new SlogLogger from a slog.Handler.
func NewLoggerFromHandler(h slog.Handler) SlogLogger {
	return &slogLogger{inner: slog.New(h)}
}

func (l *slogLogger) Write(level slog.Level, msg string, attrs ...interface{}) {
	if !l.inner.Enabled(context.Background(), level) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])
	if len(attrs)%2 != 0 {
		attrs = append(attrs, nil, "LOG_ERROR", "Normalized odd number of arguments by adding nil")
	}
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(attrs...)
	_ = l.inner.Handler().Handle(context.Background(), r)
}

func (l *slogLogger) Log(level slog.Level, msg string, attrs ...interface{}) {
	l.Write(level, msg, attrs...)
}

func (l *slogLogger) With(ctx ...interface{}) SlogLogger {
	return &slogLogger{l.inner.With(ctx...)}
}

func (l *slogLogger) New(ctx ...interface{}) SlogLogger {
	return l.With(ctx...)
}

func (l *slogLogger) Enabled(ctx context.Context, level slog.Level) bool {
	return l.inner.Enabled(ctx, level)
}

func (l *slogLogger) Trace(msg string, ctx ...interface{}) {
	l.Write(slogLevelTrace, msg, ctx...)
}

func (l *slogLogger) Debug(msg string, ctx ...interface{}) {
	l.Write(slog.LevelDebug, msg, ctx...)
}

func (l *slogLogger) Info(msg string, ctx ...interface{}) {
	l.Write(slog.LevelInfo, msg, ctx...)
}

func (l *slogLogger) Warn(msg string, ctx ...interface{}) {
	l.Write(slog.LevelWarn, msg, ctx...)
}

func (l *slogLogger) Error(msg string, ctx ...interface{}) {
	l.Write(slog.LevelError, msg, ctx...)
}

func (l *slogLogger) Crit(msg string, ctx ...interface{}) {
	l.Write(slogLevelCrit, msg, ctx...)
	os.Exit(1)
}

func (l *slogLogger) Handler() slog.Handler {
	return l.inner.Handler()
}

// FromLegacyLevel converts old geth verbosity level to slog.Level.
func FromLegacyLevel(lvl int) slog.Level {
	switch lvl {
	case legacyLevelCrit:
		return slogLevelCrit
	case legacyLevelError:
		return slog.LevelError
	case legacyLevelWarn:
		return slog.LevelWarn
	case legacyLevelInfo:
		return slog.LevelInfo
	case legacyLevelDebug:
		return slog.LevelDebug
	case legacyLevelTrace:
		return slogLevelTrace
	}
	if lvl > legacyLevelTrace {
		return slogLevelTrace
	}
	return slogLevelCrit
}

// LvlFromString returns the appropriate level from a string name.
func LvlFromString(lvlString string) (slog.Level, error) {
	switch strings.ToLower(lvlString) {
	case "trace", "trce":
		return slogLevelTrace, nil
	case "debug", "dbug":
		return slogLevelDebug, nil
	case "info":
		return slogLevelInfo, nil
	case "warn":
		return slogLevelWarn, nil
	case "error", "eror":
		return slogLevelError, nil
	case "crit":
		return slogLevelCrit, nil
	default:
		return slogLevelDebug, fmt.Errorf("unknown level: %v", lvlString)
	}
}

// LevelAlignedString returns a 5-character string containing the name of a level.
func LevelAlignedString(l slog.Level) string {
	switch l {
	case slogLevelTrace:
		return "TRACE"
	case slog.LevelDebug:
		return "DEBUG"
	case slog.LevelInfo:
		return "INFO "
	case slog.LevelWarn:
		return "WARN "
	case slog.LevelError:
		return "ERROR"
	case slogLevelCrit:
		return "CRIT "
	default:
		return "unknown"
	}
}

// LevelString returns a string containing the name of a level.
func LevelString(l slog.Level) string {
	switch l {
	case slogLevelTrace:
		return "trace"
	case slog.LevelDebug:
		return "debug"
	case slog.LevelInfo:
		return "info"
	case slog.LevelWarn:
		return "warn"
	case slog.LevelError:
		return "error"
	case slogLevelCrit:
		return "crit"
	default:
		return "unknown"
	}
}

// GlogHandler is a log handler that mimics glog behavior.
type GlogHandler struct {
	origin       slog.Handler
	verbosity    slog.Level
	vmodule      map[string]slog.Level
	patternCache map[string]*regexp.Regexp // cached compiled patterns
	mu           sync.RWMutex
}

// NewGlogHandler creates a GlogHandler wrapping the given handler.
func NewGlogHandler(h slog.Handler) *GlogHandler {
	return &GlogHandler{
		origin:       h,
		verbosity:    slogLevelInfo,
		vmodule:      make(map[string]slog.Level),
		patternCache: make(map[string]*regexp.Regexp),
	}
}

// Verbosity sets the global verbosity level.
func (h *GlogHandler) Verbosity(level slog.Level) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.verbosity = level
}

// Vmodule sets per-module verbosity patterns.
func (h *GlogHandler) Vmodule(pattern string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.vmodule = make(map[string]slog.Level)
	h.patternCache = make(map[string]*regexp.Regexp)
	if pattern == "" {
		return nil
	}

	for _, rule := range strings.Split(pattern, ",") {
		parts := strings.Split(rule, "=")
		if len(parts) != 2 {
			continue
		}
		module := strings.TrimSpace(parts[0])
		levelStr := strings.TrimSpace(parts[1])
		level, err := LvlFromString(levelStr)
		if err != nil {
			var lvl int
			if _, parseErr := fmt.Sscanf(levelStr, "%d", &lvl); parseErr == nil {
				level = FromLegacyLevel(lvl)
			} else {
				continue
			}
		}
		h.vmodule[module] = level
		// Precompile pattern regex
		if re, err := compilePattern(module); err == nil {
			h.patternCache[module] = re
		}
	}
	return nil
}

func (h *GlogHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.RLock()
	verbosity := h.verbosity
	vmodule := h.vmodule
	patternCache := h.patternCache
	h.mu.RUnlock()

	if len(vmodule) > 0 {
		_, file, _, ok := runtime.Caller(6)
		if ok {
			for pattern, level := range vmodule {
				re := patternCache[pattern]
				if re != nil && re.MatchString(file) && r.Level >= level {
					return h.origin.Handle(ctx, r)
				}
			}
		}
	}

	if r.Level >= verbosity {
		return h.origin.Handle(ctx, r)
	}
	return nil
}

// compilePattern converts a vmodule pattern to a compiled regex.
func compilePattern(pattern string) (*regexp.Regexp, error) {
	escaped := strings.ReplaceAll(pattern, ".", "\\.")
	escaped = strings.ReplaceAll(escaped, "*", ".*")
	escaped = strings.ReplaceAll(escaped, "/", "\\/")
	return regexp.Compile(escaped)
}

func (h *GlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	h.mu.RLock()
	verbosity := h.verbosity
	h.mu.RUnlock()
	return level >= verbosity
}

func (h *GlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.mu.RLock()
	verbosity := h.verbosity
	vmodule := make(map[string]slog.Level, len(h.vmodule))
	for k, v := range h.vmodule {
		vmodule[k] = v
	}
	patternCache := make(map[string]*regexp.Regexp, len(h.patternCache))
	for k, v := range h.patternCache {
		patternCache[k] = v
	}
	h.mu.RUnlock()

	return &GlogHandler{
		origin:       h.origin.WithAttrs(attrs),
		verbosity:    verbosity,
		vmodule:      vmodule,
		patternCache: patternCache,
	}
}

func (h *GlogHandler) WithGroup(name string) slog.Handler {
	h.mu.RLock()
	verbosity := h.verbosity
	vmodule := make(map[string]slog.Level, len(h.vmodule))
	for k, v := range h.vmodule {
		vmodule[k] = v
	}
	patternCache := make(map[string]*regexp.Regexp, len(h.patternCache))
	for k, v := range h.patternCache {
		patternCache[k] = v
	}
	h.mu.RUnlock()

	return &GlogHandler{
		origin:       h.origin.WithGroup(name),
		verbosity:    verbosity,
		vmodule:      vmodule,
		patternCache: patternCache,
	}
}

// TerminalHandler formats log records for human readability on a terminal.
type TerminalHandler struct {
	mu           sync.Mutex
	wr           io.Writer
	lvl          slog.Leveler
	useColor     bool
	attrs        []slog.Attr
	fieldPadding map[string]int
	buf          []byte
	Prefix       func(r slog.Record) string
}

// NewTerminalHandler returns a handler which formats log records for human readability.
func NewTerminalHandler(wr io.Writer, useColor bool) *TerminalHandler {
	return NewTerminalHandlerWithLevel(wr, levelMaxVerbosity, useColor)
}

// NewTerminalHandlerWithLevel returns a terminal handler with level filtering.
func NewTerminalHandlerWithLevel(wr io.Writer, lvl slog.Leveler, useColor bool) *TerminalHandler {
	return &TerminalHandler{
		wr:           wr,
		lvl:          lvl,
		useColor:     useColor,
		fieldPadding: make(map[string]int),
	}
}

func (h *TerminalHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	buf := h.format(h.buf, r, h.useColor)
	_, _ = h.wr.Write(buf)
	h.buf = buf[:0]
	return nil
}

func (h *TerminalHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.lvl.Level()
}

func (h *TerminalHandler) WithGroup(name string) slog.Handler {
	// Create a new handler with the group prefix applied to attribute keys
	return &TerminalHandler{
		wr:           h.wr,
		lvl:          h.lvl,
		useColor:     h.useColor,
		attrs:        h.attrs,
		fieldPadding: make(map[string]int),
		Prefix: func(r slog.Record) string {
			prefix := ""
			if h.Prefix != nil {
				prefix = h.Prefix(r)
			}
			if name != "" {
				prefix = prefix + name + "."
			}
			return prefix
		},
	}
}

func (h *TerminalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TerminalHandler{
		wr:           h.wr,
		lvl:          h.lvl,
		useColor:     h.useColor,
		attrs:        append(h.attrs, attrs...),
		fieldPadding: make(map[string]int),
	}
}

func (h *TerminalHandler) ResetFieldPadding() {
	h.mu.Lock()
	h.fieldPadding = make(map[string]int)
	h.mu.Unlock()
}

func (h *TerminalHandler) format(buf []byte, r slog.Record, usecolor bool) []byte {
	msg := escapeMessage(r.Message)
	var color = ""
	if usecolor {
		switch r.Level {
		case slogLevelCrit:
			color = "\x1b[35m"
		case slog.LevelError:
			color = "\x1b[31m"
		case slog.LevelWarn:
			color = "\x1b[33m"
		case slog.LevelInfo:
			color = "\x1b[32m"
		case slog.LevelDebug:
			color = "\x1b[36m"
		case slogLevelTrace:
			color = "\x1b[34m"
		}
	}
	if buf == nil {
		buf = make([]byte, 0, 30+termMsgJust)
	}
	b := bytes.NewBuffer(buf)

	b.WriteString("[")
	writeTimeTermFormat(b, r.Time)
	b.WriteString("] ")

	if color != "" {
		b.WriteString(color)
		b.WriteString(LevelAlignedString(r.Level))
		b.WriteString("\x1b[0m")
	} else {
		b.WriteString(LevelAlignedString(r.Level))
	}

	b.WriteByte(' ')

	if h.Prefix != nil {
		b.WriteString(h.Prefix(r))
	}

	b.WriteString(msg)

	length := len(msg)
	if (r.NumAttrs()+len(h.attrs)) > 0 && length < termMsgJust {
		b.Write(spaces[:termMsgJust-length])
	}
	h.formatAttributes(b, r, color)

	return b.Bytes()
}

func (h *TerminalHandler) formatAttributes(buf *bytes.Buffer, r slog.Record, color string) {
	var tmp = make([]byte, 40)
	writeAttr := func(attr slog.Attr, _, last bool) {
		buf.WriteByte(' ')
		if color != "" {
			buf.WriteString(color)
			buf.Write(appendEscapeString(tmp[:0], attr.Key))
			buf.WriteString("\x1b[0m=")
		} else {
			buf.Write(appendEscapeString(tmp[:0], attr.Key))
			buf.WriteByte('=')
		}
		val := FormatSlogValue(attr.Value, tmp[:0])
		padding := h.fieldPadding[attr.Key]
		length := utf8.RuneCount(val)
		if padding < length && length <= termCtxMaxPadding {
			padding = length
			h.fieldPadding[attr.Key] = padding
		}
		buf.Write(val)
		if !last && padding > length {
			buf.Write(spaces[:padding-length])
		}
	}
	var n = 0
	var nAttrs = len(h.attrs) + r.NumAttrs()
	for _, attr := range h.attrs {
		writeAttr(attr, n == 0, n == nAttrs-1)
		n++
	}
	r.Attrs(func(attr slog.Attr) bool {
		writeAttr(attr, n == 0, n == nAttrs-1)
		n++
		return true
	})
	buf.WriteByte('\n')
}

// FormatSlogValue formats a slog.Value for serialization to terminal.
func FormatSlogValue(v slog.Value, tmp []byte) (result []byte) {
	var value any
	defer func() {
		if err := recover(); err != nil {
			if v := reflect.ValueOf(value); v.Kind() == reflect.Ptr && v.IsNil() {
				result = []byte("<nil>")
			} else {
				panic(err)
			}
		}
	}()

	switch v.Kind() {
	case slog.KindString:
		return appendEscapeString(tmp, v.String())
	case slog.KindInt64:
		return appendInt64(tmp, v.Int64())
	case slog.KindUint64:
		return appendUint64(tmp, v.Uint64(), false)
	case slog.KindFloat64:
		return strconv.AppendFloat(tmp, v.Float64(), floatFormat, 3, 64)
	case slog.KindBool:
		return strconv.AppendBool(tmp, v.Bool())
	case slog.KindDuration:
		value = v.Duration()
	case slog.KindTime:
		return v.Time().AppendFormat(tmp, timeFormat)
	default:
		value = v.Any()
	}
	if value == nil {
		return []byte("<nil>")
	}
	switch v := value.(type) {
	case *big.Int:
		return appendBigInt(tmp, v)
	case error:
		return appendEscapeString(tmp, v.Error())
	case fmt.Stringer:
		return appendEscapeString(tmp, v.String())
	}
	internal := fmt.Appendf(tmp, "%+v", value)
	return appendEscapeString(tmp, string(internal))
}

func appendInt64(dst []byte, n int64) []byte {
	if n < 0 {
		return appendUint64(dst, uint64(-n), true)
	}
	return appendUint64(dst, uint64(n), false)
}

func appendUint64(dst []byte, n uint64, neg bool) []byte {
	if n < 100000 {
		if neg {
			return strconv.AppendInt(dst, -int64(n), 10)
		}
		return strconv.AppendInt(dst, int64(n), 10)
	}
	const maxLength = 26
	var (
		out   = make([]byte, maxLength)
		i     = maxLength - 1
		comma = 0
	)
	for ; n > 0; i-- {
		if comma == 3 {
			comma = 0
			out[i] = ','
		} else {
			comma++
			out[i] = '0' + byte(n%10)
			n /= 10
		}
	}
	if neg {
		out[i] = '-'
		i--
	}
	return append(dst, out[i+1:]...)
}

func appendBigInt(dst []byte, n *big.Int) []byte {
	if n.IsUint64() {
		return appendUint64(dst, n.Uint64(), false)
	}
	if n.IsInt64() {
		return appendInt64(dst, n.Int64())
	}
	var (
		text  = n.String()
		buf   = make([]byte, len(text)+len(text)/3)
		comma = 0
		i     = len(buf) - 1
	)
	for j := len(text) - 1; j >= 0; j, i = j-1, i-1 {
		c := text[j]
		switch {
		case c == '-':
			buf[i] = c
		case comma == 3:
			buf[i] = ','
			i--
			comma = 0
			fallthrough
		default:
			buf[i] = c
			comma++
		}
	}
	return append(dst, buf[i+1:]...)
}

func appendEscapeString(dst []byte, s string) []byte {
	needsQuoting := false
	needsEscaping := false
	for _, r := range s {
		if r == ' ' || r == '=' {
			needsQuoting = true
			continue
		}
		if r <= '"' || r > '~' {
			needsEscaping = true
			break
		}
	}
	if needsEscaping {
		return strconv.AppendQuote(dst, s)
	}
	if needsQuoting {
		dst = append(dst, '"')
		dst = append(dst, []byte(s)...)
		return append(dst, '"')
	}
	return append(dst, []byte(s)...)
}

func escapeMessage(s string) string {
	needsQuoting := false
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\t' {
			continue
		}
		if r < ' ' || r > '~' || r == '=' {
			needsQuoting = true
			break
		}
	}
	if !needsQuoting {
		return s
	}
	return strconv.Quote(s)
}

func writeTimeTermFormat(buf *bytes.Buffer, t time.Time) {
	_, month, day := t.Date()
	writePosIntWidth(buf, int(month), 2)
	buf.WriteByte('-')
	writePosIntWidth(buf, day, 2)
	buf.WriteByte('|')
	hour, min, sec := t.Clock()
	writePosIntWidth(buf, hour, 2)
	buf.WriteByte(':')
	writePosIntWidth(buf, min, 2)
	buf.WriteByte(':')
	writePosIntWidth(buf, sec, 2)
	ns := t.Nanosecond()
	buf.WriteByte('.')
	writePosIntWidth(buf, ns/1e6, 3)
}

func writePosIntWidth(b *bytes.Buffer, i, width int) {
	if i < 0 {
		panic("negative int")
	}
	var bb [20]byte
	bp := len(bb) - 1
	for i >= 10 || width > 1 {
		width--
		q := i / 10
		bb[bp] = byte('0' + i - q*10)
		bp--
		i = q
	}
	bb[bp] = byte('0' + i)
	b.Write(bb[bp:])
}

// JSONHandler returns a handler which prints records in JSON format.
func JSONHandler(wr io.Writer) slog.Handler {
	return slog.NewJSONHandler(wr, &slog.HandlerOptions{
		ReplaceAttr: builtinReplaceJSON,
	})
}

// JSONHandlerWithLevel returns a JSON handler with level filtering.
func JSONHandlerWithLevel(wr io.Writer, level slog.Leveler) slog.Handler {
	return slog.NewJSONHandler(wr, &slog.HandlerOptions{
		ReplaceAttr: builtinReplaceJSON,
		Level:       level,
	})
}

// LogfmtHandler returns a handler which prints records in logfmt format.
func LogfmtHandler(wr io.Writer) slog.Handler {
	return slog.NewTextHandler(wr, &slog.HandlerOptions{
		ReplaceAttr: builtinReplaceLogfmt,
	})
}

// LogfmtHandlerWithLevel returns a logfmt handler with level filtering.
func LogfmtHandlerWithLevel(wr io.Writer, level slog.Leveler) slog.Handler {
	return slog.NewTextHandler(wr, &slog.HandlerOptions{
		ReplaceAttr: builtinReplaceLogfmt,
		Level:       level,
	})
}

func builtinReplaceLogfmt(_ []string, attr slog.Attr) slog.Attr {
	return builtinReplace(nil, attr, true)
}

func builtinReplaceJSON(_ []string, attr slog.Attr) slog.Attr {
	return builtinReplace(nil, attr, false)
}

func builtinReplace(_ []string, attr slog.Attr, logfmt bool) slog.Attr {
	switch attr.Key {
	case slog.TimeKey:
		if attr.Value.Kind() == slog.KindTime {
			if logfmt {
				return slog.String("timestamp", attr.Value.Time().Format(timeFormat))
			}
			return slog.Attr{Key: "timestamp", Value: attr.Value}
		}
	case slog.LevelKey:
		if l, ok := attr.Value.Any().(slog.Level); ok {
			return slog.Any("level", LevelString(l))
		}
	}

	switch v := attr.Value.Any().(type) {
	case time.Time:
		if logfmt {
			attr = slog.String(attr.Key, v.Format(timeFormat))
		}
	case *big.Int:
		if v == nil {
			attr.Value = slog.StringValue("<nil>")
		} else {
			attr.Value = slog.StringValue(v.String())
		}
	case fmt.Stringer:
		if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
			attr.Value = slog.StringValue("<nil>")
		} else {
			attr.Value = slog.StringValue(v.String())
		}
	}
	return attr
}

// DiscardHandler returns a no-op handler.
func DiscardHandler() slog.Handler {
	return &discardHandler{}
}

type discardHandler struct{}

func (h *discardHandler) Handle(_ context.Context, r slog.Record) error    { return nil }
func (h *discardHandler) Enabled(_ context.Context, level slog.Level) bool { return false }
func (h *discardHandler) WithGroup(name string) slog.Handler               { return h }
func (h *discardHandler) WithAttrs(attrs []slog.Attr) slog.Handler         { return h }

// TerminalStringer is an interface for custom terminal serialization.
type TerminalStringer interface {
	TerminalString() string
}

// SetupTerminalLogger sets up a terminal logger with color support.
func SetupTerminalLogger(level slog.Level) SlogLogger {
	useColor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
	var output io.Writer = os.Stderr
	if useColor {
		output = colorable.NewColorableStderr()
	}
	handler := NewTerminalHandlerWithLevel(output, level, useColor)
	return NewLogger(handler)
}
