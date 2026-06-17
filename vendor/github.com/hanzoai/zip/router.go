package zip

import (
	"github.com/gofiber/fiber/v3"
)

// Router is the path-mounting surface shared by *App and Group.
// All concrete routes flow through toFiberHandler — fiber.Ctx is
// the underlying type the framework's users never see directly.
type Router interface {
	Use(handlers ...Handler) Router

	Get(path string, h Handler) Router
	Post(path string, h Handler) Router
	Put(path string, h Handler) Router
	Patch(path string, h Handler) Router
	Delete(path string, h Handler) Router
	Head(path string, h Handler) Router
	Options(path string, h Handler) Router
	All(path string, h Handler) Router

	Group(prefix string, handlers ...Handler) Router
	Route(prefix string, fn func(r Router)) Router

	// Fiber returns the underlying fiber.Router for one-off escape.
	Fiber() fiber.Router
}

// routerAdapter wraps a fiber.Router (App or Group) and exposes the
// zip-style Handler signature.
type routerAdapter struct {
	r   fiber.Router
	app *App
}

func (a *routerAdapter) Use(handlers ...Handler) Router {
	for _, h := range handlers {
		a.r.Use(toFiberHandler(a.app, h))
	}
	return a
}

func (a *routerAdapter) Get(path string, h Handler) Router {
	a.r.Get(path, toFiberHandler(a.app, h))
	return a
}

func (a *routerAdapter) Post(path string, h Handler) Router {
	a.r.Post(path, toFiberHandler(a.app, h))
	return a
}

func (a *routerAdapter) Put(path string, h Handler) Router {
	a.r.Put(path, toFiberHandler(a.app, h))
	return a
}

func (a *routerAdapter) Patch(path string, h Handler) Router {
	a.r.Patch(path, toFiberHandler(a.app, h))
	return a
}

func (a *routerAdapter) Delete(path string, h Handler) Router {
	a.r.Delete(path, toFiberHandler(a.app, h))
	return a
}

func (a *routerAdapter) Head(path string, h Handler) Router {
	a.r.Head(path, toFiberHandler(a.app, h))
	return a
}

func (a *routerAdapter) Options(path string, h Handler) Router {
	a.r.Options(path, toFiberHandler(a.app, h))
	return a
}

func (a *routerAdapter) All(path string, h Handler) Router {
	a.r.All(path, toFiberHandler(a.app, h))
	return a
}

func (a *routerAdapter) Group(prefix string, handlers ...Handler) Router {
	args := make([]any, 0, len(handlers))
	for _, h := range handlers {
		args = append(args, toFiberHandler(a.app, h))
	}
	g := a.r.Group(prefix, args...)
	return &routerAdapter{r: g, app: a.app}
}

func (a *routerAdapter) Route(prefix string, fn func(r Router)) Router {
	g := a.r.Group(prefix)
	r := &routerAdapter{r: g, app: a.app}
	fn(r)
	return r
}

func (a *routerAdapter) Fiber() fiber.Router { return a.r }

// toFiberHandler turns a zip.Handler into a fiber.Handler, materialising
// the per-request *Ctx and forwarding errors to fiber's error chain (which
// runs through zip's default errorHandler).
func toFiberHandler(app *App, h Handler) fiber.Handler {
	return func(fc fiber.Ctx) error {
		c := &Ctx{fc: fc, app: app, log: app.logger}
		return h(c)
	}
}
