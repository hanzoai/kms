package log

import (
	"context"
)

// disabledLogger is a singleton disabled logger for context operations.
var disabledLogger Logger

func init() {
	// Global level defaults to DebugLevel (zero value of Level = 0).
	// Applications that want trace output must call SetGlobalLevel(TraceLevel).
	// Do NOT reset to TraceLevel here -- it causes debug spam from dependency
	// init() functions before the application configures its own log level.
	disabledLogger = Noop()
}

type ctxKey struct{}

// WithContext returns a copy of ctx with the logger attached. The Logger
// attached to the provided Context (if any) will not be affected.
//
// Note: to modify the existing Logger attached to a Context (instead of
// replacing it in a new Context), use UpdateContext with the following
// notation:
//
//	ctx := r.Context()
//	l := logger.Ctx(ctx)
//	l.UpdateContext(func(c Context) Context {
//	    return c.Str("bar", "baz")
//	})
func WithContext(ctx context.Context, l Logger) context.Context {
	if l == nil {
		l = Noop()
	}
	return context.WithValue(ctx, ctxKey{}, l)
}

// Ctx returns the Logger associated with the ctx. If no logger
// is associated, DefaultContextLogger is returned, unless DefaultContextLogger
// is nil, in which case a disabled logger is returned.
func Ctx(ctx context.Context) Logger {
	if l, ok := ctx.Value(ctxKey{}).(Logger); ok {
		return l
	} else if l = DefaultContextLogger; l != nil {
		return l
	}
	return disabledLogger
}
