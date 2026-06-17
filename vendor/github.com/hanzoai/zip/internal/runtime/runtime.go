// Package runtime defines the minimal Loader / Module interface zip
// consumes from any HIP-0105 extension runtime implementation
// (hanzoai/base/plugins/extruntime is the reference).
//
// zip does NOT pull hanzoai/base as a dependency — instead the
// service binary constructs its own *extruntime.Loader and passes it
// in via zip.Config.Loader. The Loader interface here is duck-typed:
// any type that implements LoadDir + Close (and whose Modules
// implement Invoke + Close) satisfies it.
package runtime

import "context"

// Module is one loaded extension (HIP-0105 Module interface, projected).
type Module interface {
	Name() string
	Runtime() string
	Exports() []string
	Invoke(ctx context.Context, fn string, payload []byte) ([]byte, error)
	Close() error
}

// Loader is the projection of *extruntime.Loader zip consumes.
// Construct your loader in hanzoai/base/plugins/extruntime and pass
// it to zip.Config.Loader.
type Loader interface {
	// LoadDir scans a directory for extension manifests and returns
	// loaded modules keyed by manifest name.
	LoadDir(ctx context.Context, dir string) (map[string]Module, error)

	// LoadOne loads a single extension by directory. zip uses this for
	// app.Module() which mounts ONE extension at one route. Implementers
	// may implement this by calling LoadDir on the parent and selecting
	// the result.
	LoadOne(ctx context.Context, dir string) (Module, error)

	// Runtimes returns the registered runtime names ("goja", "wazero",
	// "v8go", "pyvm", "starlark", "native").
	Runtimes() []string
}
