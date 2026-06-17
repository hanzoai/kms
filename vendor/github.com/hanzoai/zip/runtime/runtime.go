// Package runtime is the zip-side projection of HIP-0105's extension
// runtime contract. Consumers of zip pass a Loader implementation here
// (typically *extruntime.Loader from hanzoai/base/plugins/extruntime)
// and zip mounts modules as routes via app.Module().
package runtime

import internal "github.com/hanzoai/zip/internal/runtime"

// Loader is re-exported from internal/runtime for ergonomic use:
//
//	loader := myextruntime.NewLoader(...) // implements zipruntime.Loader
//	app := zip.New(zip.Config{Loader: loader})
type Loader = internal.Loader

// Module is re-exported from internal/runtime.
type Module = internal.Module
