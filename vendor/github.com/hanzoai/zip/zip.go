// Package zip is Hanzo's canonical Go web framework. Built on
// Fiber v3 / fasthttp. Sinatra-style API. ZAP-typed handlers.
// Multi-language extension support via HIP-0105.
//
// ONE framework, ZERO escape hatches. zip IS fast.
//
//	app := zip.New(zip.Config{Logger: luxlog.NewLogger("svc")})
//	app.Use(middleware.Recover(), middleware.RequestID())
//	app.Get("/health", func(c *zip.Ctx) error {
//	    return c.JSON(200, fiber.Map{"ok": true})
//	})
//	app.Listen(":8080")
//
// Public surface — types/functions exposed at the package root:
//
//	type App, Config, Ctx, Handler
//	func New(Config) *App
//	func Get[I, O](app *App, path string, fn func(ctx, *I) (*O, error))
//	func Post[I, O](app *App, path string, fn func(ctx, *I) (*O, error))
//	...
//
// All other behavior lives in subpackages: `middleware`, `runtime`.
package zip

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v3"
	luxlog "github.com/luxfi/log"

	"github.com/hanzoai/zip/internal/jsonenc"
	"github.com/hanzoai/zip/runtime"
	"github.com/hanzoai/zip/zaprpc"
)

// JSONVariant reports which JSON implementation zip is using in this
// build — "encoding/json/v2" when compiled with GOEXPERIMENT=jsonv2,
// "encoding/json" otherwise. Exposed for cmd/cloud startup logs and
// for tests that need to assert the variant. Per HIP-0106 the wire
// stack is "JSON only at edge, ZAP between services"; this constant
// tells operators which JSON impl is on the edge.
const JSONVariant = jsonenc.Variant

// zaprpcRegistry is an alias so the App field doesn't carry a deep type
// path; full type lives in package zaprpc.
type zaprpcRegistry = zaprpc.Registry

// newZAPRegistry constructs the ZAP RPC service registry.
func newZAPRegistry() *zaprpcRegistry { return zaprpc.NewRegistry() }

// Handler is zip's request handler signature. Returning an error causes
// Fiber's error chain to write a JSON response.
type Handler func(c *Ctx) error

// Config configures the zip App. Most fields pass through to Fiber's own
// Config; a few zip-specific knobs control runtime loading.
type Config struct {
	// Logger is the luxfi/log Logger zip uses internally. Required.
	// If nil, a default one is created via luxlog.NewLogger("zip").
	Logger luxlog.Logger

	// Loader is the HIP-0105 extension runtime loader. nil disables
	// app.Module() — only native handlers will work. The interface is
	// satisfied by *extruntime.Loader from hanzoai/base/plugins/extruntime;
	// zip does NOT take a hard dep on hanzoai/base.
	Loader runtime.Loader

	// AllowedRuntimes restricts which extension runtimes app.Module()
	// will accept (e.g. ["goja","wazero"] for hard multi-tenant safety).
	// nil = allow whatever the Loader has registered.
	AllowedRuntimes []string

	// ServerHeader is sent as the Server: response header (default "zip").
	// Set to "-" to suppress.
	ServerHeader string

	// BodyLimit is the maximum request body size (default 4 MiB).
	BodyLimit int

	// AppName forwards to fiber.Config.AppName.
	AppName string

	// DisableStartupMessage suppresses Fiber's startup banner.
	DisableStartupMessage bool

	// ErrorHandler is the catch-all error handler. Defaults to zip.errorHandler
	// which renders {error, code, status} JSON.
	ErrorHandler fiber.ErrorHandler

	// OpenAPI configures the auto-generated /.well-known/openapi.json
	// served when typed handlers are registered.
	OpenAPI OpenAPIConfig
}

// App is the zip application. It wraps *fiber.App and exposes the zip
// handler signature alongside generic typed handlers.
type App struct {
	cfg         Config
	logger      luxlog.Logger
	loader      runtime.Loader
	fiber       *fiber.App
	ops         []*registeredOp
	closers     []func() error
	zapReg      *zaprpcRegistry
	zapListener interface{ Close() error }
}

// New constructs an App with the given config. Defaults are applied
// for any zero-valued field.
func New(cfg Config) *App {
	if cfg.Logger == nil {
		cfg.Logger = luxlog.New("module", "zip")
	}
	if cfg.BodyLimit == 0 {
		cfg.BodyLimit = 4 << 20
	}
	if cfg.ServerHeader == "" {
		cfg.ServerHeader = "zip"
	}

	fcfg := fiber.Config{
		AppName:   cfg.AppName,
		BodyLimit: cfg.BodyLimit,
		// Route every Fiber JSON path through zip's jsonenc package: this
		// covers c.JSON(), c.Bind().Body(), and the default error
		// handler when it serializes HTTPError. With GOEXPERIMENT=jsonv2
		// the underlying impl is encoding/json/v2; otherwise it falls
		// back to encoding/json. Same call site, different bytes-out.
		JSONEncoder: jsonenc.Marshal,
		JSONDecoder: jsonenc.Unmarshal,
	}
	if cfg.ServerHeader != "-" {
		fcfg.ServerHeader = cfg.ServerHeader
	}
	if cfg.ErrorHandler != nil {
		fcfg.ErrorHandler = cfg.ErrorHandler
	} else {
		fcfg.ErrorHandler = errorHandler
	}

	cfg.Logger.Info("zip new", "json_variant", jsonenc.Variant)

	return &App{
		cfg:    cfg,
		logger: cfg.Logger,
		loader: cfg.Loader,
		fiber:  fiber.New(fcfg),
	}
}

// Fiber returns the underlying *fiber.App. Use for one-off escape into
// Fiber-only APIs (rare). Prefer staying on the zip surface.
func (a *App) Fiber() *fiber.App { return a.fiber }

// Logger returns the App's logger.
func (a *App) Logger() luxlog.Logger { return a.logger }

// Listen starts the HTTP server on addr and blocks.
func (a *App) Listen(addr string) error {
	a.installOpenAPIRoutes()
	a.logger.Info("zip listening", "addr", addr)
	return a.fiber.Listen(addr, fiber.ListenConfig{
		DisableStartupMessage: a.cfg.DisableStartupMessage,
	})
}

// Shutdown gracefully stops the server.
func (a *App) Shutdown() error {
	_ = a.runClosers(context.Background())
	return a.fiber.Shutdown()
}

// ShutdownWithContext gracefully stops the server bounded by ctx.
func (a *App) ShutdownWithContext(ctx context.Context) error {
	_ = a.runClosers(ctx)
	return a.fiber.ShutdownWithContext(ctx)
}

// Use registers zip-style middleware. Each Handler runs in order; calling
// c.Next() (via c.Continue) chains to the next handler.
func (a *App) Use(handlers ...Handler) Router {
	for _, h := range handlers {
		a.fiber.Use(toFiberHandler(a, h))
	}
	return &routerAdapter{r: a.fiber, app: a}
}

// UseFiber lets callers register raw fiber.Handler middleware (for the
// fiber/v3/middleware/* packages). zip middleware is preferred.
func (a *App) UseFiber(handlers ...fiber.Handler) Router {
	args := make([]any, 0, len(handlers))
	for _, h := range handlers {
		args = append(args, h)
	}
	a.fiber.Use(args...)
	return &routerAdapter{r: a.fiber, app: a}
}

// Get / Post / Put / Patch / Delete / Head / Options / All / Add register routes.
func (a *App) Get(path string, h Handler) Router    { return a.method("GET", path, h) }
func (a *App) Post(path string, h Handler) Router   { return a.method("POST", path, h) }
func (a *App) Put(path string, h Handler) Router    { return a.method("PUT", path, h) }
func (a *App) Patch(path string, h Handler) Router  { return a.method("PATCH", path, h) }
func (a *App) Delete(path string, h Handler) Router { return a.method("DELETE", path, h) }
func (a *App) Head(path string, h Handler) Router   { return a.method("HEAD", path, h) }
func (a *App) Options(path string, h Handler) Router {
	return a.method("OPTIONS", path, h)
}

// All registers a handler for any HTTP method.
func (a *App) All(path string, h Handler) Router {
	a.fiber.All(path, toFiberHandler(a, h))
	return &routerAdapter{r: a.fiber, app: a}
}

func (a *App) method(method, path string, h Handler) Router {
	a.fiber.Add([]string{method}, path, toFiberHandler(a, h))
	return &routerAdapter{r: a.fiber, app: a}
}

// Group creates a path-prefixed router group.
func (a *App) Group(prefix string, handlers ...Handler) Router {
	args := make([]any, 0, len(handlers))
	for _, h := range handlers {
		args = append(args, toFiberHandler(a, h))
	}
	g := a.fiber.Group(prefix, args...)
	return &routerAdapter{r: g, app: a}
}

// Route runs fn against a path-prefixed router group.
func (a *App) Route(prefix string, fn func(r Router)) Router {
	g := a.fiber.Group(prefix)
	r := &routerAdapter{r: g, app: a}
	fn(r)
	return r
}

// errors.As helper for HTTPError unwrapping in tests / external callers.
func asHTTPError(err error) (*HTTPError, bool) {
	var he *HTTPError
	if errors.As(err, &he) {
		return he, true
	}
	return nil, false
}
