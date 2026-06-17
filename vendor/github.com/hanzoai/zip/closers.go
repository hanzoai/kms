package zip

import "context"

// appendCloser registers fn to run during Shutdown(). Used by Module()
// to release extension-runtime modules.
func (a *App) appendCloser(fn func() error) {
	a.closers = append(a.closers, fn)
}

// runClosers runs all registered closers and returns the first error.
func (a *App) runClosers(_ context.Context) error {
	var firstErr error
	for _, fn := range a.closers {
		if err := fn(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	a.closers = nil
	return firstErr
}
