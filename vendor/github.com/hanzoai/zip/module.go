package zip

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hanzoai/zip/internal/jsonenc"
)

// moduleEnvelope is the JSON shape every extension runtime receives.
// Same shape across wasm / goja / pyvm / starlark — the host serializes
// once and the guest sees the same bytes regardless of which engine ran
// it. RawMessage is from encoding/json (v1) because the type lives in
// v1 only; both v1 and v2 (encoding/json/v2) honor its MarshalJSON /
// UnmarshalJSON so the envelope serializes identically under either
// build of jsonenc.
type moduleEnvelope struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Params  map[string]string `json:"params"`
	Query   map[string]string `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body,omitempty"`

	// Hanzo identity — populated from gateway X-* headers per HIP-0026.
	Org       string `json:"org,omitempty"`
	User      string `json:"user,omitempty"`
	UserEmail string `json:"userEmail,omitempty"`
}

// moduleResponse is the JSON shape every extension runtime returns.
type moduleResponse struct {
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    json.RawMessage   `json:"body,omitempty"`
}

// Module mounts a single HIP-0105 extension at the given method+path.
// The `methodPath` form is "METHOD /path" (e.g. "POST /v1/validate"),
// matching the Sinatra/Express idiom. `runtime` selects the backing
// engine ("wasm" | "goja" | "pyvm" | "starlark" | "v8go" | "native");
// `modulePath` is the directory containing the extension.json manifest.
//
//	app.Module("POST /v1/policy/eval", "wasm", "./extensions/policy")
//	app.Module("POST /v1/transform",   "pyvm", "./extensions/transform")
//	app.Module("POST /v1/webhook",     "goja", "./extensions/webhook")
//
// The extension's exported function name is inferred from the path's
// last segment unless explicitly overridden via app.ModuleFn().
func (a *App) Module(methodPath, runtimeName, modulePath string) error {
	method, path, fn, err := parseModuleSpec(methodPath)
	if err != nil {
		return err
	}
	return a.ModuleFn(method, path, fn, runtimeName, modulePath)
}

// ModuleFn is the explicit form of Module — caller specifies the
// guest's exported function name directly.
func (a *App) ModuleFn(method, path, fn, runtimeName, modulePath string) error {
	if a.loader == nil {
		return fmt.Errorf("zip: app.Module requires Config.Loader to be set")
	}
	if a.cfg.AllowedRuntimes != nil {
		ok := false
		for _, r := range a.cfg.AllowedRuntimes {
			if r == runtimeName {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("zip: runtime %q not in AllowedRuntimes", runtimeName)
		}
	}

	mod, err := a.loader.LoadOne(nil, filepath.Clean(modulePath))
	if err != nil {
		return fmt.Errorf("zip: load module %s: %w", modulePath, err)
	}
	if got := mod.Runtime(); got != runtimeName {
		// Loader picked a different runtime than caller asked — likely a
		// manifest mismatch. Refuse to mount.
		_ = mod.Close()
		return fmt.Errorf("zip: module %s declared runtime=%q, caller passed %q", modulePath, got, runtimeName)
	}

	a.logger.Info("zip mounting module",
		"method", method, "path", path, "fn", fn,
		"runtime", runtimeName, "modulePath", modulePath)

	handler := func(c *Ctx) error {
		env := buildEnvelope(c)
		payload, err := jsonenc.Marshal(env)
		if err != nil {
			return ErrInternal("marshal envelope: " + err.Error())
		}
		out, err := mod.Invoke(c.Context(), fn, payload)
		if err != nil {
			return ErrInternal("module invoke: " + err.Error())
		}
		var resp moduleResponse
		if len(out) > 0 {
			if err := jsonenc.Unmarshal(out, &resp); err != nil {
				// Treat bare JSON output as the body with status 200.
				return c.Bytes(200, out)
			}
		}
		if resp.Status == 0 {
			resp.Status = 200
		}
		for k, v := range resp.Headers {
			c.SetHeader(k, v)
		}
		if len(resp.Body) == 0 {
			return c.NoContent(resp.Status)
		}
		// Default to application/json for module responses when no
		// Content-Type was set by the module. Modules can override via
		// the response envelope's headers map.
		if resp.Headers["Content-Type"] == "" && resp.Headers["content-type"] == "" {
			c.SetHeader("Content-Type", "application/json; charset=utf-8")
		}
		return c.Bytes(resp.Status, resp.Body)
	}
	a.method(method, path, handler)

	// Register a shutdown hook so the module's resources are released.
	// fiber doesn't expose a graceful-shutdown hook list, so we stash the
	// closer on the App and run them inline from Shutdown if needed.
	a.appendCloser(mod.Close)
	return nil
}

// parseModuleSpec parses "METHOD /path" into (method, path, fnName).
// fnName defaults to the last non-{param} path segment, lowercased.
//
//	"POST /v1/validate"            -> POST /v1/validate validate
//	"GET  /v1/users/{id}"          -> GET  /v1/users/{id} users
//	"POST /v1/foo/bar/baz"         -> POST /v1/foo/bar/baz baz
func parseModuleSpec(spec string) (method, path, fn string, err error) {
	parts := strings.Fields(spec)
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("zip: module spec %q: want \"METHOD /path\"", spec)
	}
	method = strings.ToUpper(parts[0])
	path = parts[1]
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		if s != "" && !strings.HasPrefix(s, "{") && !strings.HasPrefix(s, ":") {
			fn = strings.ToLower(s)
			break
		}
	}
	if fn == "" {
		fn = "handler"
	}
	return method, path, fn, nil
}

func buildEnvelope(c *Ctx) moduleEnvelope {
	headers := map[string]string{}
	c.fc.Request().Header.VisitAll(func(k, v []byte) {
		headers[string(k)] = string(v)
	})

	queries := map[string]string{}
	c.fc.Request().URI().QueryArgs().VisitAll(func(k, v []byte) {
		queries[string(k)] = string(v)
	})

	// Fiber v3 doesn't expose AllParams directly — common pattern is to
	// pull known params. For the envelope shape we carry the body and let
	// the guest re-parse path params from the URL if it needs them.
	return moduleEnvelope{
		Method:    c.Method(),
		Path:      c.Path(),
		Params:    map[string]string{},
		Query:     queries,
		Headers:   headers,
		Body:      c.Body(),
		Org:       c.Org(),
		User:      c.User(),
		UserEmail: c.UserEmail(),
	}
}
