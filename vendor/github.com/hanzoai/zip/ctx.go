package zip

import (
	"bufio"
	"context"
	"errors"
	"io"

	"github.com/gofiber/fiber/v3"
	luxlog "github.com/luxfi/log"
)

// Ctx wraps fiber.Ctx and adds the Hanzo identity surface (Org/User/Email
// from gateway-minted X-* headers per HIP-0026), a per-request luxfi/log
// logger, and typed Deps access.
type Ctx struct {
	fc  fiber.Ctx
	app *App
	log luxlog.Logger
}

// Fiber returns the underlying fiber.Ctx for one-off escape into Fiber-only APIs.
func (c *Ctx) Fiber() fiber.Ctx { return c.fc }

// App returns the parent App.
func (c *Ctx) App() *App { return c.app }

// Context returns the standard context.Context (deadline + cancellation).
func (c *Ctx) Context() context.Context { return c.fc.Context() }

// Log returns the request-scoped logger. Middleware that adds request_id,
// org, user, etc. via Locals can enrich this by calling SetLog.
func (c *Ctx) Log() luxlog.Logger { return c.log }

// SetLog replaces the request logger (typically by middleware that wants
// to attach request-id / org / user fields).
func (c *Ctx) SetLog(l luxlog.Logger) { c.log = l }

// ----- Hanzo identity (HIP-0026 / gateway X-* headers) ---------------------

// Org returns the X-Org-Id from the JWT-validated gateway. Empty when
// no gateway is in front (local dev / direct ingress).
func (c *Ctx) Org() string { return c.fc.Get("X-Org-Id") }

// User returns the X-User-Id from the JWT-validated gateway.
func (c *Ctx) User() string { return c.fc.Get("X-User-Id") }

// UserEmail returns the X-User-Email from the JWT-validated gateway.
func (c *Ctx) UserEmail() string { return c.fc.Get("X-User-Email") }

// IsAdmin returns the X-User-IsAdmin gateway claim as a bool.
func (c *Ctx) IsAdmin() bool { return c.fc.Get("X-User-IsAdmin") == "true" }

// RequestID returns the value of X-Request-Id (set by the RequestID middleware).
func (c *Ctx) RequestID() string { return c.fc.Get("X-Request-Id") }

// ----- request basics ------------------------------------------------------

// Method returns the request method.
func (c *Ctx) Method() string { return c.fc.Method() }

// Path returns the request path.
func (c *Ctx) Path() string { return c.fc.Path() }

// Param returns a URL path parameter.
func (c *Ctx) Param(name string) string { return c.fc.Params(name) }

// Query returns a URL query parameter.
func (c *Ctx) Query(name string) string { return c.fc.Query(name) }

// Header returns a request header.
func (c *Ctx) Header(name string) string { return c.fc.Get(name) }

// SetHeader sets a response header.
func (c *Ctx) SetHeader(name, value string) { c.fc.Set(name, value) }

// Body returns the raw request body.
func (c *Ctx) Body() []byte { return c.fc.Body() }

// Bind parses the request body into v based on Content-Type (JSON by
// default) and runs struct-tag validation (required/min/max/minlen/maxlen).
// Returns a *HTTPError(400) when either step fails so handlers can
// return the error directly.
func (c *Ctx) Bind(v any) error {
	if err := c.fc.Bind().Body(v); err != nil {
		return ErrBadRequest("invalid body: " + err.Error())
	}
	if err := validate(v); err != nil {
		return ErrBadRequest(err.Error())
	}
	return nil
}

// BindQuery parses query parameters into v and runs validation.
func (c *Ctx) BindQuery(v any) error {
	if err := c.fc.Bind().Query(v); err != nil {
		return ErrBadRequest("invalid query: " + err.Error())
	}
	if err := validate(v); err != nil {
		return ErrBadRequest(err.Error())
	}
	return nil
}

// BindURI parses URL params into v and runs validation.
func (c *Ctx) BindURI(v any) error {
	if err := c.fc.Bind().URI(v); err != nil {
		return ErrBadRequest("invalid uri: " + err.Error())
	}
	if err := validate(v); err != nil {
		return ErrBadRequest(err.Error())
	}
	return nil
}

// ----- response writers ----------------------------------------------------

// Status sets the response status. Chains.
func (c *Ctx) Status(code int) *Ctx { c.fc.Status(code); return c }

// JSON writes the value as JSON with status code.
func (c *Ctx) JSON(code int, v any) error {
	c.fc.Status(code)
	return c.fc.JSON(v)
}

// String writes a plain-text response.
func (c *Ctx) String(code int, s string) error {
	c.fc.Status(code)
	return c.fc.SendString(s)
}

// Bytes writes raw bytes.
func (c *Ctx) Bytes(code int, b []byte) error {
	c.fc.Status(code)
	return c.fc.Send(b)
}

// NoContent writes the status code with no body.
func (c *Ctx) NoContent(code int) error {
	c.fc.Status(code)
	return nil
}

// SendStream streams data from r to the client (e.g. for SSE).
func (c *Ctx) SendStream(r io.Reader) error {
	return c.fc.SendStream(r)
}

// SendStreamWriter writes streaming output via a bufio.Writer (Server-Sent
// Events / chunked transfer). Forwards to fiber.Ctx.SendStreamWriter.
func (c *Ctx) SendStreamWriter(fn func(w *bufio.Writer)) error {
	return c.fc.SendStreamWriter(fn)
}

// Locals returns or sets a per-request value.
func (c *Ctx) Locals(key any, value ...any) any {
	return c.fc.Locals(key, value...)
}

// Next yields to the next handler in the chain. Use sparingly from
// zip middleware — middleware bodies usually call c.Continue() at the
// end, not Next() mid-handler.
func (c *Ctx) Next() error { return c.fc.Next() }

// Continue is an alias for Next() with the standard middleware idiom.
func (c *Ctx) Continue() error { return c.fc.Next() }

// =============================================================================
// Errors — handlers return one of these to control status code
// =============================================================================

// HTTPError is the canonical error type zip understands. Returning one
// causes the error handler to send a JSON {error, code, status} body.
type HTTPError struct {
	Status int    `json:"status"`
	Code   string `json:"code,omitempty"`
	Msg    string `json:"error"`
}

func (e *HTTPError) Error() string { return e.Msg }

// Errorf builds an HTTPError with the given status and message.
func Errorf(status int, format string, args ...any) *HTTPError {
	return &HTTPError{Status: status, Msg: sprintf(format, args...)}
}

// Common shortcuts.
func ErrBadRequest(msg string) *HTTPError   { return &HTTPError{Status: 400, Msg: msg} }
func ErrUnauthorized(msg string) *HTTPError { return &HTTPError{Status: 401, Msg: msg} }
func ErrForbidden(msg string) *HTTPError    { return &HTTPError{Status: 403, Msg: msg} }
func ErrNotFound(msg string) *HTTPError     { return &HTTPError{Status: 404, Msg: msg} }
func ErrConflict(msg string) *HTTPError     { return &HTTPError{Status: 409, Msg: msg} }
func ErrInternal(msg string) *HTTPError     { return &HTTPError{Status: 500, Msg: msg} }

// errorHandler is the default fiber.ErrorHandler — converts HTTPError
// into a JSON response and falls back to 500 for anything else.
func errorHandler(c fiber.Ctx, err error) error {
	var he *HTTPError
	if errors.As(err, &he) {
		if he.Status == 0 {
			he.Status = 500
		}
		c.Status(he.Status)
		return c.JSON(he)
	}
	var fe *fiber.Error
	if errors.As(err, &fe) {
		c.Status(fe.Code)
		return c.JSON(&HTTPError{Status: fe.Code, Msg: fe.Message})
	}
	c.Status(500)
	return c.JSON(&HTTPError{Status: 500, Msg: err.Error()})
}
